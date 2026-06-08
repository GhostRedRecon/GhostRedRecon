#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.integrations.wifi_mk7.active_fingerprint_engine import ActiveFingerprintEngine
from backend.integrations.wifi_mk7.imported_capture_analyzer import ImportedCaptureAnalyzer


DISCOVERY_PORTS = "80,161,443,554,8000,8080,8554,10554"
HTTP_PORTS = (80, 443, 8080, 8000)
RTSP_PORTS = (554, 8554, 10554)
SNMP_PORT = 161
SNAPSHOT_PATHS = (
    "/ISAPI/Streaming/channels/101/picture",
    "/cgi-bin/snapshot.cgi",
    "/cgi-bin/currentpic.cgi",
    "/onvif/snapshot",
    "/snapshot.jpg",
    "/img/snapshot.cgi",
)
RTSP_URL_TEMPLATES = (
    "rtsp://{ip}:{port}/",
    "rtsp://{ip}:{port}/Streaming/Channels/101",
    "rtsp://{ip}:{port}/cam/realmonitor?channel=1&subtype=0",
    "rtsp://{ip}:{port}/h264Preview_01_main",
    "rtsp://{ip}:{port}/live/ch00_0",
)
SAFE_SNMP_OIDS = (
    "1.3.6.1.2.1.1.1.0",   # sysDescr.0
    "1.3.6.1.2.1.1.5.0",   # sysName.0
    "1.3.6.1.2.1.25.3.2.1.3",  # hrDeviceDescr
)
LOCAL_COMMUNITIES = ("public",)
CAMERA_VENDOR_KEYWORDS = (
    "hikvision", "dahua", "reolink", "axis", "vivotek", "hanwha", "wisenet",
    "tapo", "ezviz", "imou", "instar", "bosch", "uniview", "ubiquiti", "protect",
    "netatmo", "ring", "arlo", "wyze", "eufy", "blink", "foscam", "amcrest",
)
IMAGING_VENDOR_KEYWORDS = CAMERA_VENDOR_KEYWORDS + (
    "apple", "samsung", "google", "motorola", "xiaomi", "oneplus", "oppo",
    "vivo", "huawei", "honor", "dell", "hp", "lenovo", "asus", "acer", "msi",
    "microsoft", "logitech", "razer", "anker", "amazon", "meta", "nintendo",
)
IMAGING_HOSTNAME_KEYWORDS = (
    "cam", "camera", "doorbell", "webcam", "pet", "baby", "monitor", "vision",
    "iphone", "ipad", "pixel", "galaxy", "macbook", "laptop", "thinkpad", "surface",
)
IMAGING_DOMAIN_KEYWORDS = (
    "camera", "doorbell", "onvif", "rtsp", "stream", "snapshot", "video",
    "ring", "arlo", "wyze", "eufy", "tapo", "reolink", "hikvision", "dahua",
    "googlevideo", "facetime", "imessage", "snapchat", "zoom", "teams", "webex",
)

DEFAULT_TSHARK_FIELDS = (
    "wlan.sa",
    "wlan.da",
    "ip.src",
    "ip.dst",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.resp.name",
    "http.host",
    "http.server",
    "http.user_agent",
    "http.request.uri",
    "bootp.option.hostname",
    "bootp.option.vendor_class_id",
    "tls.handshake.extensions_server_name",
    "rtsp.method",
    "rtsp.url",
)


@dataclass
class WeightConfig:
    w_passive_rtsp: float = 18.0
    w_passive_http_surface: float = 14.0
    w_passive_vendor: float = 8.0
    w_passive_long_flow: float = 8.0
    w_passive_uplink_bias: float = 6.0
    w_imaging_vendor: float = 10.0
    w_imaging_hostname: float = 10.0
    w_imaging_domain: float = 8.0
    penalty_low_evidence: float = 8.0
    high_threshold: float = 70.0
    medium_threshold: float = 35.0

    @staticmethod
    def load(path: str) -> "WeightConfig":
        cfg = WeightConfig()
        if not path:
            return cfg
        candidate = Path(path).expanduser()
        if not candidate.exists():
            return cfg
        try:
            data = json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return cfg
        for key, value in (data or {}).items():
            if hasattr(cfg, key) and isinstance(value, (int, float)):
                setattr(cfg, key, float(value))
        return cfg


def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def log(message: str) -> None:
    print(f"[camera-hunt] {message}", flush=True)


def tool_path(name: str) -> str:
    return shutil.which(name) or ""


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).is_private
    except ValueError:
        return False


def sha256_file(path: Path, *, max_bytes: int = 128 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    read_bytes = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read_bytes += len(chunk)
            if read_bytes >= max_bytes:
                break
    return digest.hexdigest()


def run_command(args: List[str], *, cwd: Path | None = None, timeout: int = 300) -> Dict[str, Any]:
    started = time.time()
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "elapsed_seconds": round(time.time() - started, 2),
            "command": args,
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "elapsed_seconds": round(time.time() - started, 2),
            "command": args,
        }


def maybe_sudo(args: List[str], enabled: bool) -> List[str]:
    return (["sudo", "-n"] + args) if enabled else args


def api_request(base_url: str, method: str, path: str, *, timeout: int = 30, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    query = urllib.parse.urlencode(params or {}, doseq=True)
    url = f"{base_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{query}"
    request = urllib.request.Request(url, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="ignore")
            return json.loads(payload or "{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        return {"ok": False, "error": f"HTTP {exc.code}", "body": body, "url": url}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "url": url}


class GhostReconCameraHunt:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root_dir = REPO_ROOT
        self.logs_dir = Path(args.logs_dir).expanduser() if args.logs_dir else (self.root_dir / "logs" / "wifi_mk7")
        self.evidence_dir = self.root_dir / "evidence"
        self.image_dir = self.evidence_dir / "camera_images"
        self.run_dir = self.evidence_dir / "camera_hunt_runs" / now_ts()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.tools = {
            name: tool_path(name)
            for name in (
                "tshark",
                "zeek",
                "nmap",
                "ffmpeg",
                "exiftool",
                "binwalk",
                "tcpflow",
                "foremost",
                "curl",
                "file",
                "arp-scan",
                "snmpwalk",
                "nbtscan",
                "kismet",
                "kismetdb_dump_devices",
                "ip",
                "iw",
            )
        }
        self.weights = WeightConfig.load(self.args.weights_json)
        self.active_engine = ActiveFingerprintEngine(root_dir=self.root_dir, preferred_interface=self.args.interface)
        self.manifest: Dict[str, Any] = {
            "started_at": int(time.time()),
            "root_dir": str(self.root_dir),
            "run_dir": str(self.run_dir),
            "image_dir": str(self.image_dir),
            "logs_dir": str(self.logs_dir),
            "args": vars(args),
            "tools": self.tools,
            "weights": vars(self.weights),
            "orchestration": [],
            "approaches": [],
            "saved_images": [],
        }
        self.saved_images: List[Dict[str, Any]] = []
        self.device_profiles: Dict[str, Dict[str, Any]] = {}
        self.passive_signals: Dict[str, Any] = {}
        self.kismet_logs: List[str] = []
        self.interface_window_state: Dict[str, Any] = {}
        self.seen_hashes: Set[str] = set()

    def run(self) -> int:
        log(f"run directory: {self.run_dir}")
        self._orchestrate()
        self._score_profiles()
        self._report()
        log(f"profiles: {len(self.device_profiles)}")
        log(f"saved images: {len(self.saved_images)}")
        return 0

    def _orchestrate(self) -> None:
        self._step("live_capture", self._approach_live_capture)
        pcaps = self._select_pcaps()
        if pcaps:
            self._step("imported_analysis", lambda: self._approach_imported_analysis(pcaps))
            self._step("passive_decode", lambda: self._approach_passive_decode(pcaps))
            self._step("carving", lambda: self._approach_carving(pcaps))
        else:
            self._record_approach("imported_analysis", {"ok": False, "reason": "no_pcaps"})
            self._record_approach("passive_decode", {"ok": False, "reason": "no_pcaps"})
            self._record_approach("carving", {"ok": False, "reason": "no_pcaps"})

        if self.args.cidr:
            self._step("local_discovery", self._approach_local_discovery)
        else:
            self._record_approach("local_discovery", {"ok": False, "reason": "no_cidr"})

        self._step("kismet_logs", self._approach_kismet_logs)
        self._step("active_probing", self._approach_active_probing)

    def _step(self, name: str, callback: Any) -> None:
        started = time.time()
        result = callback()
        self.manifest["orchestration"].append(
            {
                "step": name,
                "elapsed_seconds": round(time.time() - started, 2),
                "ok": bool((result or {}).get("ok", True)),
            }
        )

    def _record_approach(self, name: str, payload: Dict[str, Any]) -> None:
        entry = {"name": name, **payload}
        self.manifest["approaches"].append(entry)
        write_json(self.run_dir / f"{name}.json", entry)

    def _profile(self, key: str) -> Dict[str, Any]:
        profile = self.device_profiles.setdefault(
            key,
            {
                "device_id": key,
                "ips": [],
                "macs": [],
                "hostnames": [],
                "vendors": [],
                "families": [],
                "domains": [],
                "open_ports": [],
                "passive": {
                    "sources": [],
                    "traffic_behavior": {},
                    "camera_signals": [],
                    "rtsp_hints": 0,
                    "http_hints": 0,
                    "vendor_hints": 0,
                    "observed_server_ports": [],
                    "observed_client_ports": [],
                    "flow": {
                        "long_lived_flow": False,
                        "uplink_ratio": None,
                    },
                },
                "active": {
                    "tools_run": [],
                    "rtsp": {"available": False, "evidence": []},
                    "snapshot": {"success": False, "images": []},
                    "http": {"camera_positive": False, "findings": []},
                    "snmp": {"positive": False, "findings": []},
                    "nbt": {"positive": False, "findings": []},
                },
                "confidence": {
                    "camera_score": 0.0,
                    "imaging_score": 0.0,
                    "priority_score": 0.0,
                    "tier": "LOW",
                    "reasons": [],
                    "missing_evidence": [],
                },
                "device_hypothesis": {
                    "likely_type": "unknown",
                    "imaging_capable": False,
                    "camera_specific": False,
                    "reasons": [],
                },
                "report_summary": "",
            },
        )
        return profile

    def _merge_value(self, values: List[str], value: str) -> None:
        if value and value not in values:
            values.append(value)

    def _add_ip(self, profile: Dict[str, Any], ip_value: str) -> None:
        if is_private_ip(ip_value):
            self._merge_value(profile["ips"], ip_value)

    def _add_vendor(self, profile: Dict[str, Any], vendor: str) -> None:
        if vendor:
            self._merge_value(profile["vendors"], vendor)
            lowered = vendor.lower()
            if any(token in lowered for token in CAMERA_VENDOR_KEYWORDS):
                profile["passive"]["vendor_hints"] += 1
            if any(token in lowered for token in IMAGING_VENDOR_KEYWORDS):
                self._merge_value(profile["passive"]["camera_signals"], "imaging_vendor_family")

    def _route_interface(self, ip_value: str) -> str:
        if not self.tools["ip"]:
            return ""
        result = run_command([self.tools["ip"], "route", "get", ip_value], timeout=10)
        if not result.get("ok"):
            return ""
        tokens = str(result.get("stdout") or "").split()
        for index, token in enumerate(tokens):
            if token == "dev" and index + 1 < len(tokens):
                return tokens[index + 1].strip()
        return ""

    def _mk7_route_ok(self, ip_value: str) -> Tuple[bool, str]:
        route_interface = self._route_interface(ip_value)
        return route_interface == self.args.interface, route_interface

    def _iw_dev_dump(self) -> str:
        if not self.tools["iw"]:
            return ""
        result = run_command(maybe_sudo([self.tools["iw"], "dev"], self.args.sudo_local_tools), timeout=15)
        return str(result.get("stdout") or "")

    def _interface_link_state(self, interface: str) -> Dict[str, Any]:
        if not self.tools["iw"]:
            return {"ok": False, "error": "iw not installed"}
        link = run_command(maybe_sudo([self.tools["iw"], "dev", interface, "link"], self.args.sudo_local_tools), timeout=15)
        stdout = str(link.get("stdout") or "")
        connected = "Connected to" in stdout and "Not connected." not in stdout
        ssid = ""
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID:"):
                ssid = stripped.split(":", 1)[1].strip()
        return {
            "ok": bool(link.get("ok")),
            "connected": connected,
            "ssid": ssid,
            "raw": stdout,
            "stderr": str(link.get("stderr") or ""),
        }

    def _with_managed_discovery_window(self, callback: Any) -> Dict[str, Any]:
        state: Dict[str, Any] = {
            "ok": True,
            "base_interface": self.args.interface,
            "monitor_interface": f"{self.args.interface}mon",
            "pre_iw_dev": self._iw_dev_dump(),
            "pre_link": self._interface_link_state(self.args.interface),
            "actions": [],
        }
        if not self.args.managed_discovery_window:
            payload = callback(state)
            state["post_iw_dev"] = self._iw_dev_dump()
            state["post_link"] = self._interface_link_state(self.args.interface)
            payload["managed_window"] = state
            return payload

        monitor_interface = f"{self.args.interface}mon"
        if monitor_interface in state["pre_iw_dev"]:
            down_result = run_command(maybe_sudo(["ip", "link", "set", monitor_interface, "down"], self.args.sudo_local_tools), timeout=15)
            delete_result = run_command(maybe_sudo([self.tools["iw"], "dev", monitor_interface, "del"], self.args.sudo_local_tools), timeout=15)
            state["actions"].append({"step": "delete_monitor_interface", "down": down_result, "delete": delete_result})
        payload = callback(state)
        restore_add = run_command(
            maybe_sudo([self.tools["iw"], "phy", self.args.phy_name, "interface", "add", monitor_interface, "type", "monitor"], self.args.sudo_local_tools),
            timeout=20,
        )
        restore_up = run_command(maybe_sudo(["ip", "link", "set", monitor_interface, "up"], self.args.sudo_local_tools), timeout=15)
        state["actions"].append({"step": "restore_monitor_interface", "add": restore_add, "up": restore_up})
        state["post_iw_dev"] = self._iw_dev_dump()
        state["post_link"] = self._interface_link_state(self.args.interface)
        payload["managed_window"] = state
        return payload

    def _approach_live_capture(self) -> Dict[str, Any]:
        if self.args.skip_live_capture:
            payload = {"ok": False, "skipped": True, "reason": "skip_live_capture"}
            self._record_approach("live_capture", payload)
            return payload
        log("live capture: MK7AC API scan")
        clear_payload = api_request(self.args.base_url, "POST", "/api/wifi_mk7/clear")
        start_payload = api_request(
            self.args.base_url,
            "POST",
            "/api/wifi_mk7/start",
            timeout=30,
            params={
                "auto_scan": "true",
                "bands": ["2.4ghz", "5ghz"],
                "dwell_ms": self.args.dwell_ms,
                "duration_seconds": self.args.duration,
                "scan_mode": "broad",
                "interfaces": self.args.interface,
                "camera_hunt": "true",
            },
        )
        status_samples: List[Dict[str, Any]] = []
        deadline = time.time() + int(self.args.duration) + 90
        while time.time() < deadline:
            status = api_request(self.args.base_url, "GET", "/api/wifi_mk7/status", timeout=20)
            status_samples.append(status)
            if not bool(status.get("capture_active")):
                break
            time.sleep(5)
        results_payload = api_request(self.args.base_url, "GET", "/api/wifi_mk7/camera_hunt/results", timeout=30)
        pcap_payload = api_request(self.args.base_url, "GET", "/api/wifi_mk7/pcap", timeout=30)
        payload = {
            "ok": not bool(start_payload.get("error")),
            "clear": clear_payload,
            "start": start_payload,
            "final_status": status_samples[-1] if status_samples else {},
            "status_sample_count": len(status_samples),
            "results": results_payload,
            "pcap": pcap_payload,
        }
        self._record_approach("live_capture", payload)
        return payload

    def _select_pcaps(self) -> List[Path]:
        if self.args.pcap:
            return [Path(item).expanduser() for item in self.args.pcap if Path(item).expanduser().exists()]
        return sorted(self.logs_dir.glob("*.pcap*"), key=lambda item: item.stat().st_mtime, reverse=True)[: max(1, int(self.args.pcap_limit))]

    def _approach_imported_analysis(self, pcaps: List[Path]) -> Dict[str, Any]:
        log("passive imported analysis")
        analyzer = ImportedCaptureAnalyzer(self.root_dir)
        results: List[Dict[str, Any]] = []
        for pcap in pcaps:
            analysis = analyzer.analyze(str(pcap), replay=True)
            results.append({"pcap": str(pcap), "analysis": analysis})
            for collection_name in ("networks", "clients"):
                for item in analysis.get(collection_name) or []:
                    self._merge_profile_from_analysis(item, source=f"imported:{pcap.name}")
        payload = {"ok": True, "pcap_count": len(pcaps), "results": results}
        self._record_approach("imported_analysis", payload)
        return payload

    def _merge_profile_from_analysis(self, item: Dict[str, Any], *, source: str) -> None:
        key = str(item.get("bssid") or item.get("mac") or item.get("record_id") or source)
        profile = self._profile(key)
        self._merge_value(profile["passive"]["sources"], source)
        mac_value = str(item.get("bssid") or item.get("mac") or "").strip()
        if mac_value:
            self._merge_value(profile["macs"], mac_value)
        hostname = str(item.get("ssid") or item.get("hostname") or "").strip()
        if hostname and hostname not in {"<hidden>", "--"}:
            self._merge_value(profile["hostnames"], hostname)
            lowered_hostname = hostname.lower()
            if any(token in lowered_hostname for token in IMAGING_HOSTNAME_KEYWORDS):
                self._merge_value(profile["passive"]["camera_signals"], "imaging_hostname_hint")
        self._add_vendor(profile, str(item.get("vendor") or ""))
        camera_detection = dict(item.get("camera_detection") or {})
        classification = str(camera_detection.get("classification") or "").strip()
        if classification:
            self._merge_value(profile["families"], classification)
        if bool(camera_detection.get("detected")):
            self._merge_value(profile["passive"]["camera_signals"], "camera_detection.detected")
        profile["passive"]["traffic_behavior"] = {
            "mobility_class": item.get("mobility_class"),
            "traffic_pattern": item.get("traffic_pattern"),
            "historical_captures": item.get("historical_captures"),
            "observation_capture_count": item.get("observation_capture_count"),
        }
        flow_metrics = dict(item.get("flow_metrics") or {})
        if bool(flow_metrics.get("long_lived_flow")):
            self._merge_value(profile["passive"]["camera_signals"], "long_lived_flow")
        if float(flow_metrics.get("uplink_ratio") or 0.0) >= 0.55:
            self._merge_value(profile["passive"]["camera_signals"], "uplink_biased_traffic")
        service_exposure = dict(item.get("service_exposure") or {})
        protocols = list(service_exposure.get("protocols") or [])
        if "RTSP" in protocols:
            profile["passive"]["rtsp_hints"] += 1
        if "HTTP" in protocols:
            profile["passive"]["http_hints"] += 1
        for domain in dict(item.get("recurring_domain_profiles") or {}):
            domain_value = str(domain)
            self._merge_value(profile["domains"], domain_value)
            if any(token in domain_value.lower() for token in IMAGING_DOMAIN_KEYWORDS):
                self._merge_value(profile["passive"]["camera_signals"], "imaging_domain_hint")
        for ip_value in dict(item.get("destination_ip_counts") or {}):
            self._add_ip(profile, str(ip_value))
        for ip_value in dict((item.get("stable_fingerprint") or {}).get("recurring_destination_ips") or {}):
            self._add_ip(profile, str(ip_value))
        for entry in item.get("evidence_provenance") or []:
            related_ip = str(entry.get("related_ip") or "").strip()
            related_domain = str(entry.get("related_domain") or "").strip()
            self._add_ip(profile, related_ip)
            if related_domain:
                self._merge_value(profile["domains"], related_domain)

    def _approach_passive_decode(self, pcaps: List[Path]) -> Dict[str, Any]:
        log("passive decode: tshark, zeek, and object export")
        tshark_dir = self.run_dir / "tshark"
        zeek_dir = self.run_dir / "zeek"
        tshark_dir.mkdir(parents=True, exist_ok=True)
        zeek_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []

        def decode_one(pcap: Path) -> Dict[str, Any]:
            entry: Dict[str, Any] = {"pcap": str(pcap)}
            if self.tools["tshark"]:
                csv_path = tshark_dir / f"{pcap.stem}_fields.csv"
                args = [
                    self.tools["tshark"],
                    "-r",
                    str(pcap),
                    "-T",
                    "fields",
                    "-E",
                    "header=y",
                    "-E",
                    "separator=,",
                    "-E",
                    "quote=d",
                ]
                for field_name in DEFAULT_TSHARK_FIELDS:
                    args.extend(["-e", field_name])
                extract = run_command(args, timeout=int(self.args.tshark_timeout))
                csv_path.write_text(str(extract.get("stdout") or ""), encoding="utf-8")
                entry["tshark_fields"] = {k: v for k, v in extract.items() if k != "stdout"}
                entry["tshark_fields"]["csv_path"] = str(csv_path)
                self._parse_tshark_csv(csv_path, source=f"tshark:{pcap.name}")
                export_dir = tshark_dir / f"{pcap.stem}_http_objects"
                export_dir.mkdir(parents=True, exist_ok=True)
                export = run_command([self.tools["tshark"], "-r", str(pcap), "--export-objects", f"http,{export_dir}"], timeout=int(self.args.tshark_timeout))
                entry["http_export"] = export
                self._harvest_media(export_dir, source=f"tshark_export:{pcap.name}")
            else:
                entry["tshark_fields"] = {"ok": False, "error": "tshark not installed"}

            if self.tools["zeek"]:
                output_dir = zeek_dir / pcap.stem
                output_dir.mkdir(parents=True, exist_ok=True)
                zeek = run_command([self.tools["zeek"], "-Cr", str(pcap), "LogAscii::use_json=T"], cwd=output_dir, timeout=int(self.args.zeek_timeout))
                entry["zeek"] = {k: v for k, v in zeek.items() if k not in {"stdout", "stderr"}}
                self._parse_zeek_logs(output_dir, source=f"zeek:{pcap.name}")
            else:
                entry["zeek"] = {"ok": False, "error": "zeek not installed"}
            return entry

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(self.args.max_workers))) as executor:
            for entry in executor.map(decode_one, pcaps):
                results.append(entry)
        payload = {"ok": True, "results": results}
        self._record_approach("passive_decode", payload)
        return payload

    def _parse_tshark_csv(self, csv_path: Path, *, source: str) -> None:
        if not csv_path.exists():
            return
        with csv_path.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                endpoint_pairs = (
                    (str(row.get("ip.src") or row.get("arp.src.proto_ipv4") or "").strip(), str(row.get("wlan.sa") or "").strip()),
                    (str(row.get("ip.dst") or row.get("arp.dst.proto_ipv4") or "").strip(), str(row.get("wlan.da") or "").strip()),
                )
                for ip_value, mac_value in endpoint_pairs:
                    profile = self._profile(mac_value or ip_value or "unresolved")
                    self._merge_value(profile["passive"]["sources"], source)
                    self._add_ip(profile, ip_value)
                    if mac_value:
                        self._merge_value(profile["macs"], mac_value)

                    for port_field in ("tcp.srcport", "udp.srcport"):
                        value = str(row.get(port_field) or "").strip()
                        if value.isdigit():
                            port = int(value)
                            if port not in profile["passive"]["observed_client_ports"]:
                                profile["passive"]["observed_client_ports"].append(port)
                    for port_field in ("tcp.dstport", "udp.dstport"):
                        value = str(row.get(port_field) or "").strip()
                        if value.isdigit():
                            port = int(value)
                            if port not in profile["passive"]["observed_server_ports"]:
                                profile["passive"]["observed_server_ports"].append(port)

                    for field_name in ("dns.qry.name", "dns.resp.name", "http.host", "tls.handshake.extensions_server_name"):
                        value = str(row.get(field_name) or "").strip()
                        if value:
                            self._merge_value(profile["domains"], value)
                            if any(token in value.lower() for token in IMAGING_DOMAIN_KEYWORDS):
                                self._merge_value(profile["passive"]["camera_signals"], "imaging_domain_hint")

                    http_server = str(row.get("http.server") or "").strip().lower()
                    http_user_agent = str(row.get("http.user_agent") or "").strip().lower()
                    http_uri = str(row.get("http.request.uri") or "").strip().lower()
                    if http_server:
                        profile["passive"]["http_hints"] += 1
                    if any(token in http_server for token in ("camera", "onvif", "rtsp", "hikvision", "reolink", "dahua")):
                        profile["passive"]["http_hints"] += 1
                        self._merge_value(profile["passive"]["camera_signals"], "http_server_banner_cameraish")
                    if any(token in http_user_agent for token in ("ipcam", "camera", "onvif", "rtsp")):
                        profile["passive"]["http_hints"] += 1
                        self._merge_value(profile["passive"]["camera_signals"], "http_user_agent_cameraish")
                    if any(token in http_uri for token in ("snapshot", "onvif", "stream", "isapi")):
                        profile["passive"]["http_hints"] += 1
                        self._merge_value(profile["passive"]["camera_signals"], "http_camera_surface_token")

                    if str(row.get("rtsp.method") or "").strip() or str(row.get("rtsp.url") or "").strip():
                        profile["passive"]["rtsp_hints"] += 1
                        self._merge_value(profile["passive"]["camera_signals"], "rtsp_seen")

                    hostname = str(row.get("bootp.option.hostname") or "").strip()
                    if hostname:
                        self._merge_value(profile["hostnames"], hostname)
                        if any(token in hostname.lower() for token in IMAGING_HOSTNAME_KEYWORDS):
                            self._merge_value(profile["passive"]["camera_signals"], "imaging_hostname_hint")
                    self._add_vendor(profile, str(row.get("bootp.option.vendor_class_id") or ""))

    def _parse_zeek_logs(self, output_dir: Path, *, source: str) -> None:
        for name in ("conn.log", "dns.log", "http.log", "ssl.log", "x509.log", "dhcp.log", "files.log", "quic.log"):
            path = output_dir / name
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = str(record.get("id.orig_h") or record.get("id.resp_h") or source)
                    profile = self._profile(key)
                    self._merge_value(profile["passive"]["sources"], source)
                    for field_name in ("id.orig_h", "id.resp_h", "assigned_ip", "host_addr"):
                        self._add_ip(profile, str(record.get(field_name) or ""))
                    if name == "conn.log":
                        duration = record.get("duration")
                        if isinstance(duration, (int, float)) and float(duration) >= float(self.args.long_flow_seconds):
                            profile["passive"]["flow"]["long_lived_flow"] = True
                            self._merge_value(profile["passive"]["camera_signals"], "long_lived_flow")
                        resp_port = record.get("id.resp_p")
                        if isinstance(resp_port, int) and resp_port not in profile["passive"]["observed_server_ports"]:
                            profile["passive"]["observed_server_ports"].append(resp_port)
                        orig_bytes = record.get("orig_bytes")
                        resp_bytes = record.get("resp_bytes")
                        if isinstance(orig_bytes, (int, float)) and isinstance(resp_bytes, (int, float)) and (orig_bytes + resp_bytes) > 0:
                            uplink_ratio = float(orig_bytes) / float(orig_bytes + resp_bytes)
                            profile["passive"]["flow"]["uplink_ratio"] = uplink_ratio
                            if uplink_ratio >= 0.55:
                                self._merge_value(profile["passive"]["camera_signals"], "uplink_biased_traffic")
                    for field_name in ("query", "host", "server_name", "san_dns"):
                        value = record.get(field_name)
                        if isinstance(value, str) and value:
                            self._merge_value(profile["domains"], value)
                            if any(token in value.lower() for token in IMAGING_DOMAIN_KEYWORDS):
                                self._merge_value(profile["passive"]["camera_signals"], "imaging_domain_hint")
                    if name == "http.log":
                        uri = str(record.get("uri") or "").lower()
                        if any(token in uri for token in ("snapshot", "onvif", "stream", "isapi")):
                            profile["passive"]["http_hints"] += 1
                            self._merge_value(profile["passive"]["camera_signals"], "http_camera_surface_token")
                    if name == "dhcp.log":
                        hostname = str(record.get("host_name") or "").strip()
                        if hostname:
                            self._merge_value(profile["hostnames"], hostname)
                            if any(token in hostname.lower() for token in IMAGING_HOSTNAME_KEYWORDS):
                                self._merge_value(profile["passive"]["camera_signals"], "imaging_hostname_hint")
                    for field_name in ("subject", "issuer", "filename", "mime_type"):
                        value = record.get(field_name)
                        if isinstance(value, str) and value:
                            self._merge_value(profile["families"], value)

    def _approach_carving(self, pcaps: List[Path]) -> Dict[str, Any]:
        log("carving: foremost, tcpflow, binwalk")
        carve_dir = self.run_dir / "carving"
        carve_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        for pcap in pcaps:
            entry: Dict[str, Any] = {"pcap": str(pcap)}
            if self.tools["foremost"]:
                target = carve_dir / f"{pcap.stem}_foremost"
                entry["foremost"] = {k: v for k, v in run_command([self.tools["foremost"], "-i", str(pcap), "-o", str(target)], timeout=int(self.args.carve_timeout)).items() if k not in {"stdout", "stderr"}}
                self._harvest_media(target, source=f"foremost:{pcap.name}")
            else:
                entry["foremost"] = {"ok": False, "error": "foremost not installed"}
            if self.tools["tcpflow"]:
                target = carve_dir / f"{pcap.stem}_tcpflow"
                target.mkdir(parents=True, exist_ok=True)
                entry["tcpflow"] = {k: v for k, v in run_command([self.tools["tcpflow"], "-r", str(pcap), "-o", str(target)], timeout=int(self.args.carve_timeout)).items() if k not in {"stdout", "stderr"}}
                self._harvest_media(target, source=f"tcpflow:{pcap.name}")
            else:
                entry["tcpflow"] = {"ok": False, "error": "tcpflow not installed"}
            if self.tools["binwalk"]:
                entry["binwalk"] = {k: v for k, v in run_command([self.tools["binwalk"], str(pcap)], timeout=int(self.args.carve_timeout)).items() if k not in {"stdout", "stderr"}}
            else:
                entry["binwalk"] = {"ok": False, "error": "binwalk not installed"}
            results.append(entry)
        payload = {"ok": True, "results": results}
        self._record_approach("carving", payload)
        return payload

    def _approach_local_discovery(self) -> Dict[str, Any]:
        log("local discovery: arp-scan and safe local inventory")
        def runner(state: Dict[str, Any]) -> Dict[str, Any]:
            results: Dict[str, Any] = {
                "ok": True,
                "arp_scan": {},
                "nmap_discovery": {},
                "ip_neigh": {},
                "iw_scan": {},
                "link_state": state.get("pre_link") or {},
                "hosts": [],
            }
            self._seed_from_neighbor_cache(results)
            self._seed_from_nmap_discovery(results)
            self._seed_from_iw_scan(results)
            if self.tools["arp-scan"]:
                arp_scan = run_command(
                    maybe_sudo(
                        [self.tools["arp-scan"], "--localnet", "--interface", self.args.interface, "--retry=2", "--timeout=500", "--format=${ip}\t${mac}\t${vendor}"],
                        self.args.sudo_local_tools,
                    ),
                    timeout=120,
                )
                results["arp_scan"] = {k: v for k, v in arp_scan.items() if k != "stdout"}
                results["arp_scan"]["raw_path"] = str(self.run_dir / "arp_scan.txt")
                (self.run_dir / "arp_scan.txt").write_text(str(arp_scan.get("stdout") or ""), encoding="utf-8")
                for raw_line in str(arp_scan.get("stdout") or "").splitlines():
                    parts = [part.strip() for part in raw_line.split("\t")]
                    if len(parts) >= 2 and is_private_ip(parts[0]):
                        ip_value = parts[0]
                        mac_value = parts[1]
                        vendor = parts[2] if len(parts) > 2 else ""
                        profile = self._profile(ip_value)
                        self._add_ip(profile, ip_value)
                        self._merge_value(profile["macs"], mac_value)
                        self._add_vendor(profile, vendor)
                        self._merge_value(profile["passive"]["sources"], "arp-scan")
                        results["hosts"].append({"ip": ip_value, "mac": mac_value, "vendor": vendor, "source": "arp-scan"})
            else:
                results["arp_scan"] = {"ok": False, "error": "arp-scan not installed"}
            return results

        payload = self._with_managed_discovery_window(runner)
        self._record_approach("local_discovery", payload)
        return payload

    def _seed_from_neighbor_cache(self, results: Dict[str, Any]) -> None:
        if not self.tools["ip"]:
            results["ip_neigh"] = {"ok": False, "error": "ip tool not installed"}
            return
        neigh = run_command([self.tools["ip"], "neigh", "show", "dev", self.args.interface], timeout=15)
        results["ip_neigh"] = {k: v for k, v in neigh.items() if k != "stdout"}
        results["ip_neigh"]["raw_path"] = str(self.run_dir / "ip_neigh.txt")
        (self.run_dir / "ip_neigh.txt").write_text(str(neigh.get("stdout") or ""), encoding="utf-8")
        for raw_line in str(neigh.get("stdout") or "").splitlines():
            parts = raw_line.split()
            if len(parts) < 5 or not is_private_ip(parts[0]):
                continue
            ip_value = parts[0].strip()
            mac_value = parts[4].strip() if parts[3] == "lladdr" else ""
            profile = self._profile(ip_value)
            self._add_ip(profile, ip_value)
            if mac_value:
                self._merge_value(profile["macs"], mac_value)
            self._merge_value(profile["passive"]["sources"], "ip-neigh")
            results["hosts"].append({"ip": ip_value, "mac": mac_value, "vendor": "", "source": "ip-neigh"})

    def _seed_from_iw_scan(self, results: Dict[str, Any]) -> None:
        if not self.tools["iw"]:
            results["iw_scan"] = {"ok": False, "error": "iw not installed"}
            return
        scan = run_command(maybe_sudo([self.tools["iw"], "dev", self.args.interface, "scan"], self.args.sudo_local_tools), timeout=60)
        results["iw_scan"] = {k: v for k, v in scan.items() if k != "stdout"}
        results["iw_scan"]["raw_path"] = str(self.run_dir / "iw_scan.txt")
        (self.run_dir / "iw_scan.txt").write_text(str(scan.get("stdout") or ""), encoding="utf-8")
        current_bss = ""
        current_ssid = ""
        current_vendor = ""
        for raw_line in str(scan.get("stdout") or "").splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                if current_bss:
                    profile = self._profile(current_bss)
                    self._merge_value(profile["macs"], current_bss)
                    if current_ssid:
                        self._merge_value(profile["hostnames"], current_ssid)
                        if any(token in current_ssid.lower() for token in IMAGING_HOSTNAME_KEYWORDS):
                            self._merge_value(profile["passive"]["camera_signals"], "imaging_hostname_hint")
                    if current_vendor:
                        self._add_vendor(profile, current_vendor)
                    self._merge_value(profile["passive"]["sources"], "iw-scan")
                current_bss = line.split()[1].strip("()")
                current_ssid = ""
                current_vendor = ""
            elif line.startswith("SSID:"):
                current_ssid = line.split(":", 1)[1].strip()
            elif "Manufacturer:" in line or "Model:" in line:
                current_vendor = f"{current_vendor} {line}".strip()
        if current_bss:
            profile = self._profile(current_bss)
            self._merge_value(profile["macs"], current_bss)
            if current_ssid:
                self._merge_value(profile["hostnames"], current_ssid)
                if any(token in current_ssid.lower() for token in IMAGING_HOSTNAME_KEYWORDS):
                    self._merge_value(profile["passive"]["camera_signals"], "imaging_hostname_hint")
            if current_vendor:
                self._add_vendor(profile, current_vendor)
            self._merge_value(profile["passive"]["sources"], "iw-scan")

    def _seed_from_nmap_discovery(self, results: Dict[str, Any]) -> None:
        if not self.args.cidr or not self.tools["nmap"]:
            results["nmap_discovery"] = {"ok": False, "error": "nmap discovery skipped"}
            return
        xml_path = self.run_dir / "local_discovery_nmap.xml"
        scan = run_command(
            [
                self.tools["nmap"],
                "-sn",
                "-n",
                "-PR",
                "-e",
                self.args.interface,
                "-oX",
                str(xml_path),
                self.args.cidr,
            ],
            timeout=180,
        )
        results["nmap_discovery"] = {k: v for k, v in scan.items() if k not in {"stdout", "stderr"}}
        results["nmap_discovery"]["xml_path"] = str(xml_path)
        if not xml_path.exists():
            return
        try:
            root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            ip_value = ""
            mac_value = ""
            vendor = ""
            for address in host.findall("address"):
                if address.get("addrtype") == "ipv4":
                    ip_value = str(address.get("addr") or "").strip()
                elif address.get("addrtype") == "mac":
                    mac_value = str(address.get("addr") or "").strip()
                    vendor = str(address.get("vendor") or "").strip()
            if not is_private_ip(ip_value):
                continue
            profile = self._profile(ip_value)
            self._add_ip(profile, ip_value)
            if mac_value:
                self._merge_value(profile["macs"], mac_value)
            self._add_vendor(profile, vendor)
            self._merge_value(profile["passive"]["sources"], "nmap-host-discovery")
            results["hosts"].append({"ip": ip_value, "mac": mac_value, "vendor": vendor, "source": "nmap-host-discovery"})

    def _approach_kismet_logs(self) -> Dict[str, Any]:
        log("kismet integration: latest local logs if present")
        if not self.tools["kismetdb_dump_devices"]:
            payload = {"ok": False, "reason": "kismetdb_dump_devices_missing"}
            self._record_approach("kismet_logs", payload)
            return payload
        search_roots = [
            self.root_dir,
            Path.home() / "Kismet",
            Path("/var/log"),
        ]
        candidates: List[Path] = []
        for base in search_roots:
            if not base.exists():
                continue
            candidates.extend(base.glob("**/*.kismet"))
            candidates.extend(base.glob("**/*.kismetdb"))
        candidates = sorted({item for item in candidates if item.is_file()}, key=lambda item: item.stat().st_mtime, reverse=True)[:2]
        results: List[Dict[str, Any]] = []
        for kismet_db in candidates:
            output = self.run_dir / f"{safe_name(kismet_db.name)}.devices.json"
            dump = run_command([self.tools["kismetdb_dump_devices"], "-i", str(kismet_db), "-o", str(output), "-f", "-j"], timeout=180)
            entry = {"db_path": str(kismet_db), "dump": {k: v for k, v in dump.items() if k not in {"stdout", "stderr"}}, "output_path": str(output)}
            if output.exists():
                self.kismet_logs.append(str(kismet_db))
                self._parse_kismet_dump(output)
            results.append(entry)
        payload = {"ok": True, "candidate_log_count": len(candidates), "results": results}
        self._record_approach("kismet_logs", payload)
        return payload

    def _parse_kismet_dump(self, output_path: Path) -> None:
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return
        for record in payload if isinstance(payload, list) else []:
            key = str(record.get("kismet_device_base_macaddr") or record.get("kismet_device_key") or "kismet")
            profile = self._profile(key)
            self._merge_value(profile["passive"]["sources"], "kismet")
            self._merge_value(profile["macs"], str(record.get("kismet_device_base_macaddr") or ""))
            self._add_vendor(profile, str(record.get("kismet_device_base_manuf") or ""))
            for ip_value in record.get("kismet_device_base_ipdata") or []:
                if isinstance(ip_value, dict):
                    self._add_ip(profile, str(ip_value.get("kismet_common_ipdata_address") or ""))

    def _approach_active_probing(self) -> Dict[str, Any]:
        log("active orchestration: threaded safe probes")
        scored_hosts = self._select_active_targets()
        active_dir = self.run_dir / "active"
        active_dir.mkdir(parents=True, exist_ok=True)
        results: Dict[str, Any] = {"ok": True, "target_count": len(scored_hosts), "targets": scored_hosts, "hosts": []}
        if not scored_hosts:
            self._record_approach("active_probing", results)
            return results
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(self.args.max_threads))) as executor:
            future_map = {executor.submit(self._probe_host, item["ip"], active_dir): item["ip"] for item in scored_hosts}
            for future in concurrent.futures.as_completed(future_map):
                results["hosts"].append(future.result())
        self._record_approach("active_probing", results)
        return results

    def _select_active_targets(self) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        for profile in self.device_profiles.values():
            if not profile["ips"]:
                continue
            ip_value = profile["ips"][0]
            passive_weight = 0.0
            passive_weight += 12.0 * float(profile["passive"]["rtsp_hints"])
            passive_weight += 8.0 * float(profile["passive"]["http_hints"])
            passive_weight += 10.0 * float(profile["passive"]["vendor_hints"])
            passive_weight += 6.0 * len(profile["domains"])
            if "uplink_biased_traffic" in profile["passive"]["camera_signals"]:
                passive_weight += 15.0
            if "long_lived_flow" in profile["passive"]["camera_signals"]:
                passive_weight += 10.0
            if "imaging_vendor_family" in profile["passive"]["camera_signals"]:
                passive_weight += 10.0
            if "imaging_hostname_hint" in profile["passive"]["camera_signals"]:
                passive_weight += 10.0
            if "imaging_domain_hint" in profile["passive"]["camera_signals"]:
                passive_weight += 8.0
            if profile["ips"]:
                passive_weight += 4.0
            profile["confidence"]["priority_score"] = round(passive_weight, 1)
            if passive_weight >= float(self.args.min_priority_score):
                targets.append({"device_id": profile["device_id"], "ip": ip_value, "priority_score": passive_weight})
        targets.sort(key=lambda item: item["priority_score"], reverse=True)
        return targets[: int(self.args.max_active_hosts)]

    def _probe_host(self, ip_value: str, active_dir: Path) -> Dict[str, Any]:
        profile = self._profile(ip_value)
        ok_route, route_interface = self._mk7_route_ok(ip_value)
        result: Dict[str, Any] = {
            "ip": ip_value,
            "route_interface": route_interface,
            "mk7_route_ok": ok_route,
            "tools_run": [],
            "http": [],
            "rtsp": [],
            "snapshot": [],
            "snmp": [],
            "nbt": [],
            "nmap": {},
        }

        if not ok_route:
            profile["confidence"]["missing_evidence"].append(f"route via {route_interface or 'unknown'} instead of {self.args.interface}")
            profile["report_summary"] = f"Skipped active validation because route uses {route_interface or 'unknown'}, not {self.args.interface}."
            return result

        if self.tools["nmap"]:
            xml_path = active_dir / f"{safe_name(ip_value)}.xml"
            nmap_result = run_command(
                [
                    self.tools["nmap"],
                    "-Pn",
                    "-n",
                    "-sT",
                    "-sV",
                    "--version-light",
                    "-p",
                    DISCOVERY_PORTS,
                    "--script",
                    "http-title,http-headers,rtsp-methods",
                    "-oX",
                    str(xml_path),
                    ip_value,
                ],
                timeout=180,
            )
            result["tools_run"].append("nmap")
            result["nmap"] = {k: v for k, v in nmap_result.items() if k not in {"stdout", "stderr"}}
            result["nmap"]["xml_path"] = str(xml_path)
            self._merge_nmap_profile(profile, xml_path)

        http_candidates = list(profile["open_ports"] or [])
        if not any(port in HTTP_PORTS for port in http_candidates):
            http_candidates.extend(HTTP_PORTS)
        if not any(port in RTSP_PORTS for port in http_candidates):
            http_candidates.extend(RTSP_PORTS)

        if any(port in HTTP_PORTS for port in http_candidates):
            result["tools_run"].append("curl")
            result["http"] = self._http_probe_adaptive(ip_value)
            result["snapshot"] = self._snapshot_probe_adaptive(ip_value, active_dir)
            self._merge_http_snapshot_profile(profile, result["http"], result["snapshot"])
        if any(port in RTSP_PORTS for port in http_candidates):
            result["tools_run"].append("ffmpeg")
            result["rtsp"] = self._rtsp_probe_adaptive(ip_value, active_dir)
            self._merge_rtsp_profile(profile, result["rtsp"])
        if SNMP_PORT in profile["open_ports"] and self.tools["snmpwalk"]:
            result["tools_run"].append("snmpwalk")
            result["snmp"] = self._snmp_probe(ip_value)
            self._merge_snmp_profile(profile, result["snmp"])
        if self.tools["nbtscan"]:
            result["tools_run"].append("nbtscan")
            result["nbt"] = self._nbt_probe(ip_value)
            self._merge_nbt_profile(profile, result["nbt"])
        return result

    def _merge_nmap_profile(self, profile: Dict[str, Any], xml_path: Path) -> None:
        if not xml_path.exists():
            return
        try:
            root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_id = int(port.get("portid") or 0)
                if port_id and port_id not in profile["open_ports"]:
                    profile["open_ports"].append(port_id)
                service = port.find("service")
                if service is not None:
                    product = str(service.get("product") or service.get("name") or "").strip()
                    if product:
                        self._merge_value(profile["families"], product)
                        self._add_vendor(profile, product)

    def _http_probe_adaptive(self, ip_value: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        adaptive_paths = list(SNAPSHOT_PATHS) + ["/", "/doc/page/login.asp", "/onvif/device_service"]
        for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8000)):
            for path in adaptive_paths[: int(self.args.max_http_paths)]:
                target = f"{scheme}://{ip_value}:{port}{path}"
                result = run_command(
                    [
                        self.tools["curl"],
                        "-kfsS",
                        "--max-time",
                        str(int(self.args.http_timeout)),
                        "-I",
                        target,
                    ],
                    timeout=max(10, int(self.args.http_timeout) + 2),
                )
                entry = {
                    "ok": bool(result.get("ok")),
                    "scheme": scheme,
                    "port": port,
                    "path": path,
                    "headers": str(result.get("stdout") or "")[:1000],
                }
                findings.append(entry)
        return findings

    def _snapshot_probe_adaptive(self, ip_value: str, active_dir: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        attempts = 0
        for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8000)):
            for path in SNAPSHOT_PATHS:
                attempts += 1
                target = active_dir / f"{safe_name(ip_value)}_{scheme}_{port}_{safe_name(path.strip('/') or 'root')}"
                result = run_command(
                    [
                        self.tools["curl"],
                        "-kfsS",
                        "--max-time",
                        str(int(self.args.http_timeout)),
                        "-o",
                        str(target),
                        f"{scheme}://{ip_value}:{port}{path}",
                    ],
                    timeout=max(10, int(self.args.http_timeout) + 2),
                )
                finding: Dict[str, Any] = {"ok": bool(result.get("ok")), "scheme": scheme, "port": port, "path": path, "saved_path": ""}
                if target.exists():
                    validated = self._validate_and_copy_media(target, source=f"snapshot:{ip_value}:{port}{path}")
                    finding["saved_path"] = validated.get("copied_path") or ""
                    finding["validation"] = validated
                findings.append(finding)
                if finding.get("saved_path"):
                    return findings
                if attempts >= int(self.args.max_snapshot_attempts):
                    return findings
        return findings

    def _rtsp_probe_adaptive(self, ip_value: str, active_dir: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        attempts = 0
        for port in RTSP_PORTS:
            for template in RTSP_URL_TEMPLATES:
                attempts += 1
                url = template.format(ip=ip_value, port=port)
                target = active_dir / f"{safe_name(ip_value)}_{port}_{attempts}.jpg"
                result = run_command(
                    [
                        self.tools["ffmpeg"],
                        "-v",
                        "error",
                        "-nostdin",
                        "-y",
                        "-rtsp_transport",
                        "tcp",
                        "-timeout",
                        str(int(self.args.rtsp_timeout * 1000000)),
                        "-i",
                        url,
                        "-frames:v",
                        "1",
                        str(target),
                    ],
                    timeout=max(10, int(self.args.rtsp_timeout) + 4),
                )
                finding: Dict[str, Any] = {"ok": bool(result.get("ok")), "url": url, "saved_path": ""}
                if target.exists():
                    validated = self._validate_and_copy_media(target, source=f"rtsp:{url}")
                    finding["saved_path"] = validated.get("copied_path") or ""
                    finding["validation"] = validated
                findings.append(finding)
                if finding.get("saved_path"):
                    return findings
                if attempts >= int(self.args.max_rtsp_attempts):
                    return findings
        return findings

    def _snmp_probe(self, ip_value: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for community in LOCAL_COMMUNITIES:
            for oid in SAFE_SNMP_OIDS:
                result = run_command(
                    [self.tools["snmpwalk"], "-v", "2c", "-c", community, "-t", "1", "-r", "0", ip_value, oid],
                    timeout=15,
                )
                findings.append(
                    {
                        "ok": bool(result.get("ok")),
                        "community": community,
                        "oid": oid,
                        "output": str(result.get("stdout") or "")[:1200],
                    }
                )
                if result.get("ok"):
                    return findings
        return findings

    def _nbt_probe(self, ip_value: str) -> List[Dict[str, Any]]:
        result = run_command([self.tools["nbtscan"], "-q", "-s", "\t", ip_value], timeout=20)
        return [{"ok": bool(result.get("ok")), "output": str(result.get("stdout") or "")[:1200]}]

    def _merge_http_snapshot_profile(self, profile: Dict[str, Any], http_findings: List[Dict[str, Any]], snapshot_findings: List[Dict[str, Any]]) -> None:
        profile["active"]["tools_run"].extend(["curl"])
        for finding in http_findings:
            if "headers" in finding:
                profile["active"]["http"]["findings"].append(finding)
                header_blob = str(finding.get("headers") or "").lower()
                if any(token in header_blob for token in ("onvif", "camera", "hikvision", "dahua", "reolink", "axis", "rtsp")):
                    profile["active"]["http"]["camera_positive"] = True
        for finding in snapshot_findings:
            if finding.get("saved_path"):
                profile["active"]["snapshot"]["success"] = True
                profile["active"]["snapshot"]["images"].append(finding["saved_path"])

    def _merge_rtsp_profile(self, profile: Dict[str, Any], rtsp_findings: List[Dict[str, Any]]) -> None:
        profile["active"]["tools_run"].extend(["ffmpeg"])
        for finding in rtsp_findings:
            if finding.get("saved_path"):
                profile["active"]["rtsp"]["available"] = True
                profile["active"]["rtsp"]["evidence"].append(finding)

    def _merge_snmp_profile(self, profile: Dict[str, Any], snmp_findings: List[Dict[str, Any]]) -> None:
        profile["active"]["tools_run"].extend(["snmpwalk"])
        for finding in snmp_findings:
            if finding.get("ok"):
                profile["active"]["snmp"]["positive"] = True
                profile["active"]["snmp"]["findings"].append(finding)
                blob = str(finding.get("output") or "").lower()
                self._add_vendor(profile, blob)

    def _merge_nbt_profile(self, profile: Dict[str, Any], nbt_findings: List[Dict[str, Any]]) -> None:
        profile["active"]["tools_run"].extend(["nbtscan"])
        for finding in nbt_findings:
            output = str(finding.get("output") or "")
            if output.strip():
                profile["active"]["nbt"]["positive"] = True
                profile["active"]["nbt"]["findings"].append(finding)

    def _harvest_media(self, source_dir: Path, *, source: str) -> None:
        if not source_dir.exists():
            return
        for path in source_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.stat().st_size == 0 or path.stat().st_size > int(self.args.max_candidate_file_mb) * 1024 * 1024:
                continue
            self._validate_and_copy_media(path, source=source)

    def _validate_and_copy_media(self, path: Path, *, source: str) -> Dict[str, Any]:
        mime_type = ""
        if self.tools["file"]:
            file_result = run_command([self.tools["file"], "--brief", "--mime-type", str(path)], timeout=15)
            mime_type = str(file_result.get("stdout") or "").strip()
        metadata: Dict[str, Any] = {"path": str(path), "source": source, "mime_type": mime_type, "copied_path": "", "sha256": "", "exif": None}
        if not mime_type.startswith("image/") and path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".gif"}:
            return metadata
        digest = sha256_file(path)
        metadata["sha256"] = digest
        if digest in self.seen_hashes:
            return metadata
        self.seen_hashes.add(digest)
        self.image_dir.mkdir(parents=True, exist_ok=True)
        target = self.image_dir / f"{now_ts()}_{path.name}"
        suffix = 1
        while target.exists():
            target = self.image_dir / f"{now_ts()}_{suffix}_{path.name}"
            suffix += 1
        try:
            shutil.copy2(path, target)
            metadata["copied_path"] = str(target)
            if self.tools["exiftool"]:
                exif_result = run_command([self.tools["exiftool"], "-json", str(target)], timeout=30)
                if exif_result.get("ok") and exif_result.get("stdout"):
                    try:
                        metadata["exif"] = json.loads(str(exif_result["stdout"]))[0]
                    except Exception:
                        metadata["exif"] = None
            sidecar = target.with_suffix(target.suffix + ".json")
            sidecar.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")
            self.saved_images.append(metadata)
        except OSError:
            pass
        return metadata

    def _score_profiles(self) -> None:
        weights = self.weights
        for profile in self.device_profiles.values():
            reasons: List[str] = []
            missing: List[str] = []
            camera_score = 0.0
            imaging_score = 0.0
            signals = set(profile["passive"]["camera_signals"])
            if profile["passive"]["rtsp_hints"] > 0 or "rtsp_seen" in signals:
                camera_score += weights.w_passive_rtsp
                imaging_score += weights.w_passive_rtsp * 0.6
                reasons.append("RTSP observed in passive traffic")
            else:
                missing.append("RTSP traffic")
            if profile["passive"]["http_hints"] > 0 or {"http_camera_surface_token", "http_server_banner_cameraish", "http_user_agent_cameraish"} & signals:
                camera_score += weights.w_passive_http_surface
                imaging_score += weights.w_passive_http_surface * 0.7
                reasons.append("camera-like HTTP surface observed")
            else:
                missing.append("camera-like HTTP surface")
            if profile["passive"]["vendor_hints"] > 0:
                camera_score += min(15.0, weights.w_passive_vendor * float(profile["passive"]["vendor_hints"]))
                imaging_score += min(15.0, weights.w_passive_vendor * float(profile["passive"]["vendor_hints"]))
                reasons.append("vendor fingerprint matches camera families")
            else:
                missing.append("camera-family vendor match")
            if "uplink_biased_traffic" in signals or float(profile["passive"]["flow"].get("uplink_ratio") or 0.0) >= 0.55:
                camera_score += weights.w_passive_uplink_bias
                imaging_score += weights.w_passive_uplink_bias * 0.8
                reasons.append("uplink-biased traffic behavior")
            if "long_lived_flow" in signals or bool(profile["passive"]["flow"].get("long_lived_flow")):
                camera_score += weights.w_passive_long_flow
                imaging_score += weights.w_passive_long_flow * 0.7
                reasons.append("long-lived traffic flow")
            if "imaging_vendor_family" in signals:
                imaging_score += weights.w_imaging_vendor
                reasons.append("vendor belongs to imaging-capable ecosystem")
            if "imaging_hostname_hint" in signals:
                imaging_score += weights.w_imaging_hostname
                reasons.append("hostname suggests imaging-capable device")
            if "imaging_domain_hint" in signals:
                imaging_score += weights.w_imaging_domain
                reasons.append("domain activity suggests imaging/video stack")
            if profile["active"]["rtsp"]["available"]:
                camera_score += 38.0
                imaging_score += 28.0
                reasons.append("RTSP frame capture succeeded")
            else:
                missing.append("RTSP frame capture")
            if profile["active"]["snapshot"]["success"]:
                camera_score += 42.0
                imaging_score += 35.0
                reasons.append("HTTP snapshot succeeded")
            else:
                missing.append("HTTP snapshot")
            if profile["passive"]["vendor_hints"] > 0:
                vendor_points = min(15.0, 5.0 * profile["passive"]["vendor_hints"])
                camera_score += vendor_points
                imaging_score += vendor_points
                reasons.append("vendor fingerprint matches camera families")
            else:
                missing.append("camera-family vendor match")
            if "uplink_biased_traffic" in signals:
                camera_score += 10.0
                imaging_score += 8.0
            if "long_lived_flow" in signals:
                camera_score += 8.0
                imaging_score += 6.0
            if "imaging_vendor_family" in signals:
                imaging_score += 16.0
            if "imaging_hostname_hint" in signals:
                imaging_score += 14.0
            if "imaging_domain_hint" in signals:
                imaging_score += 12.0
            if profile["active"]["http"]["camera_positive"]:
                camera_score += 15.0
                imaging_score += 10.0
                reasons.append("camera-positive HTTP headers")
            if profile["active"]["snmp"]["positive"]:
                camera_score += 6.0
                imaging_score += 6.0
                reasons.append("SNMP device identity available")
            evidence_count = (
                int(profile["passive"]["rtsp_hints"] > 0)
                + int(profile["passive"]["http_hints"] > 0)
                + int(profile["passive"]["vendor_hints"] > 0)
                + int("imaging_domain_hint" in signals)
                + int(profile["active"]["snapshot"]["success"])
                + int(profile["active"]["rtsp"]["available"])
            )
            if evidence_count <= 1:
                camera_score = max(0.0, camera_score - weights.penalty_low_evidence)
                imaging_score = max(0.0, imaging_score - (weights.penalty_low_evidence * 0.6))
            imaging_capable = imaging_score >= 20.0 or bool(
                profile["active"]["snapshot"]["success"]
                or profile["active"]["rtsp"]["available"]
                or {"imaging_vendor_family", "imaging_hostname_hint", "imaging_domain_hint"} & signals
            )
            likely_type = "unknown"
            hypothesis_reasons: List[str] = []
            combined_hostnames = " ".join(profile["hostnames"]).lower()
            combined_vendors = " ".join(profile["vendors"]).lower()
            if profile["active"]["snapshot"]["success"] or profile["active"]["rtsp"]["available"] or profile["active"]["http"]["camera_positive"]:
                likely_type = "camera_or_video_endpoint"
                hypothesis_reasons.append("direct image or video service evidence")
            elif any(token in combined_hostnames for token in ("doorbell", "ring")):
                likely_type = "doorbell_or_entry_cam"
                hypothesis_reasons.append("doorbell-style hostname")
            elif any(token in combined_hostnames for token in ("pet", "baby", "monitor")):
                likely_type = "monitoring_device"
                hypothesis_reasons.append("monitor-style hostname")
            elif any(token in combined_vendors for token in ("apple", "samsung", "google", "xiaomi", "oneplus", "motorola", "oppo", "vivo", "huawei")):
                likely_type = "phone_or_tablet_with_camera"
                hypothesis_reasons.append("mobile vendor family")
            elif any(token in combined_vendors for token in ("dell", "hp", "lenovo", "asus", "acer", "microsoft", "msi")):
                likely_type = "computer_with_webcam"
                hypothesis_reasons.append("computer vendor family")
            elif "imaging_vendor_family" in signals:
                likely_type = "imaging_capable_iot_device"
                hypothesis_reasons.append("imaging-capable vendor family")
            tier = "LOW"
            if camera_score >= weights.high_threshold or imaging_score >= weights.high_threshold:
                tier = "HIGH"
            elif camera_score >= weights.medium_threshold or imaging_score >= weights.medium_threshold:
                tier = "MEDIUM"
            profile["confidence"]["camera_score"] = round(min(camera_score, 100.0), 1)
            profile["confidence"]["imaging_score"] = round(min(imaging_score, 100.0), 1)
            profile["confidence"]["tier"] = tier
            profile["confidence"]["reasons"] = reasons
            profile["confidence"]["missing_evidence"] = sorted(set(missing + profile["confidence"]["missing_evidence"]))
            profile["device_hypothesis"] = {
                "likely_type": likely_type,
                "imaging_capable": imaging_capable,
                "camera_specific": profile["confidence"]["camera_score"] >= 35.0,
                "reasons": sorted(set(hypothesis_reasons + reasons))[:8],
            }
            vendor = ", ".join(profile["vendors"][:2]) or "unknown vendor"
            ips = ", ".join(profile["ips"][:2]) or "no IP"
            profile["report_summary"] = (
                f"{ips} | {vendor} | camera {profile['confidence']['camera_score']:.1f} "
                f"| imaging {profile['confidence']['imaging_score']:.1f} | {likely_type}"
            )

    def _report(self) -> None:
        profiles = sorted(self.device_profiles.values(), key=lambda item: (item["confidence"]["camera_score"], item["confidence"]["priority_score"]), reverse=True)
        report = {
            "generated_at": int(time.time()),
            "mk7_interface": self.args.interface,
            "run_dir": str(self.run_dir),
            "image_dir": str(self.image_dir),
            "summary": {
                "profile_count": len(profiles),
                "high_confidence_camera_candidates": sum(1 for item in profiles if item["confidence"]["tier"] == "HIGH"),
                "medium_confidence_camera_candidates": sum(1 for item in profiles if item["confidence"]["tier"] == "MEDIUM"),
                "imaging_capable_candidates": sum(1 for item in profiles if item["device_hypothesis"]["imaging_capable"]),
                "saved_image_count": len(self.saved_images),
                "kismet_logs_used": self.kismet_logs,
            },
            "top_targets": profiles[: min(10, len(profiles))],
            "profiles": profiles,
            "saved_images": self.saved_images,
        }
        self.manifest["saved_images"] = self.saved_images
        write_json(self.run_dir / "intelligence_report.json", report)
        write_json(self.run_dir / "run_manifest.json", self.manifest)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Adaptive MK7AC-first GhostRedRecon camera hunt orchestrator")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--interface", default="wlan1", help="MK7AC base interface")
    parser.add_argument("--duration", type=int, default=300, help="Live capture duration in seconds")
    parser.add_argument("--dwell-ms", type=int, default=1200, help="Channel dwell time in milliseconds")
    parser.add_argument("--logs-dir", default="", help="Override logs directory; defaults to repo logs/wifi_mk7")
    parser.add_argument("--weights-json", default="", help="Optional JSON file overriding passive scoring weights")
    parser.add_argument("--pcap-limit", type=int, default=8, help="Recent pcap files to inspect")
    parser.add_argument("--pcap", action="append", default=[], help="Specific pcap/pcapng file to inspect")
    parser.add_argument("--cidr", default="", help="Local network CIDR for safe local discovery")
    parser.add_argument("--skip-live-capture", action="store_true", help="Use existing pcap evidence only")
    parser.add_argument("--sudo-local-tools", action="store_true", help="Use sudo -n for local raw-socket discovery tools like arp-scan")
    parser.add_argument("--managed-discovery-window", action="store_true", help="Temporarily remove wlan1mon, run managed discovery on wlan1, then restore monitor mode")
    parser.add_argument("--phy-name", default="1", help="Numeric phy suffix for MK7AC restore operations, e.g. 1 for phy#1")
    parser.add_argument("--max-workers", type=int, default=4, help="Parallel workers for passive pcap decode")
    parser.add_argument("--tshark-timeout", type=int, default=240, help="Seconds per tshark decode stage")
    parser.add_argument("--zeek-timeout", type=int, default=360, help="Seconds per Zeek decode stage")
    parser.add_argument("--carve-timeout", type=int, default=360, help="Seconds per carving tool run")
    parser.add_argument("--long-flow-seconds", type=float, default=20.0, help="Connection duration threshold for long-lived flow tagging")
    parser.add_argument("--max-threads", type=int, default=6, help="Thread pool size for active probes")
    parser.add_argument("--max-active-hosts", type=int, default=12, help="Maximum scored hosts for active probes")
    parser.add_argument("--min-priority-score", type=float, default=8.0, help="Minimum passive priority score before active probing")
    parser.add_argument("--http-timeout", type=float, default=4.0, help="HTTP timeout in seconds")
    parser.add_argument("--rtsp-timeout", type=float, default=5.0, help="RTSP timeout in seconds")
    parser.add_argument("--max-http-paths", type=int, default=10, help="Maximum HTTP paths to try per host")
    parser.add_argument("--max-snapshot-attempts", type=int, default=16, help="Maximum snapshot attempts per host")
    parser.add_argument("--max-rtsp-attempts", type=int, default=12, help="Maximum RTSP attempts per host")
    parser.add_argument("--max-candidate-file-mb", type=int, default=8, help="Skip carved files larger than this")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    runner = GhostReconCameraHunt(args)
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
