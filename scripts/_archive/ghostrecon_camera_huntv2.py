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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# -----------------------------------------------------------------------------
# Repo plumbing (kept compatible with your existing layout)
# -----------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    # Optional: keep compatibility with your existing analyzers.
    from backend.integrations.wifi_mk7.imported_capture_analyzer import ImportedCaptureAnalyzer
except Exception:
    ImportedCaptureAnalyzer = None  # type: ignore

# -----------------------------------------------------------------------------
# Constants & heuristics (passive-first; avoid hard-coded exploit paths)
# -----------------------------------------------------------------------------
DEFAULT_TSHARK_FIELDS = [
    # L2 / L3 identity
    "wlan.sa", "wlan.da",
    "eth.src", "eth.dst",
    "ip.src", "ip.dst",
    "arp.src.proto_ipv4", "arp.dst.proto_ipv4",

    # L4 ports (critical for service inference)
    "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport",

    # Naming / identity
    "bootp.option.hostname",
    "bootp.option.vendor_class_id",
    "dns.qry.name", "dns.resp.name",
    "tls.handshake.extensions_server_name",

    # HTTP / RTSP surface (passive)
    "http.host", "http.user_agent", "http.request.uri",
    "http.server",
    "rtsp.method", "rtsp.url",
]

IMAGING_VENDOR_KEYWORDS = (
    "hikvision", "dahua", "reolink", "axis", "vivotek", "hanwha", "wisenet",
    "tapo", "ezviz", "imou", "instar", "bosch", "uniview", "ubiquiti",
    "netatmo", "ring", "arlo", "wyze", "eufy", "blink", "foscam", "amcrest",
    "apple", "samsung", "google", "motorola", "xiaomi", "oneplus", "oppo",
    "vivo", "huawei", "honor", "dell", "hp", "lenovo", "asus", "acer", "msi",
    "microsoft", "logitech",
)

IMAGING_HOSTNAME_KEYWORDS = (
    "cam", "camera", "doorbell", "webcam", "pet", "baby", "monitor", "vision",
    "iphone", "ipad", "pixel", "galaxy", "macbook", "laptop", "thinkpad", "surface",
)

IMAGING_DOMAIN_KEYWORDS = (
    "camera", "doorbell", "onvif", "rtsp", "stream", "snapshot", "video",
    "ring", "arlo", "wyze", "eufy", "tapo", "reolink", "hikvision", "dahua",
)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")

def log(msg: str) -> None:
    print(f"[camera-hunt-v2] {msg}", flush=True)

def tool_path(name: str) -> str:
    return shutil.which(name) or ""

def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).is_private
    except ValueError:
        return False

def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or ""))

def sha256_file(path: Path, max_bytes: int = 128 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    read = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
            if read > max_bytes:
                # guard against pathological huge files
                break
    return h.hexdigest()

def run_command(args: List[str], *, cwd: Optional[Path] = None, timeout: int = 300) -> Dict[str, Any]:
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

def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")

# -----------------------------------------------------------------------------
# Data model
# -----------------------------------------------------------------------------
@dataclass
class WeightConfig:
    # camera-specific evidence families
    w_rtsp_seen: float = 22.0
    w_http_cam_surface: float = 18.0
    w_camera_vendor: float = 10.0
    w_long_lived_flow: float = 10.0
    w_uplink_bias: float = 8.0

    # imaging-capable evidence families
    w_imaging_vendor: float = 10.0
    w_imaging_hostname: float = 10.0
    w_imaging_domain: float = 8.0

    # penalties / dampening
    penalty_low_evidence: float = 8.0

    # tier thresholds
    high_threshold: float = 70.0
    medium_threshold: float = 35.0

    @staticmethod
    def load(path: Optional[str]) -> "WeightConfig":
        cfg = WeightConfig()
        if not path:
            return cfg
        p = Path(path).expanduser()
        if not p.exists():
            return cfg
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return cfg
        for k, v in (data or {}).items():
            if hasattr(cfg, k) and isinstance(v, (int, float)):
                setattr(cfg, k, float(v))
        return cfg

def _empty_profile(profile_id: str) -> Dict[str, Any]:
    return {
        "device_id": profile_id,
        "ips": [],
        "macs": [],
        "hostnames": [],
        "vendors": [],
        "domains": [],

        # Observed services and behaviors (passive)
        "observed_server_ports": [],
        "observed_client_ports": [],
        "passive": {
            "sources": [],
            "signals": [],
            "rtsp_seen": 0,
            "http_cam_surface_seen": 0,
            "vendor_hints": 0,
            "flow": {
                "long_lived_flow": False,
                "uplink_ratio": None,
            },
        },

        # Evidence artifacts (passive extraction only)
        "evidence": {
            "http_objects": [],
            "images": [],
        },

        "confidence": {
            "camera_score": 0.0,
            "imaging_score": 0.0,
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
    }

# -----------------------------------------------------------------------------
# Main orchestrator (passive-first)
# -----------------------------------------------------------------------------
class GhostReconCameraHuntV2:
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
                "file",
                "exiftool",
                "foremost",
                "tcpflow",
                "binwalk",
                "kismetdb_dump_devices",
            )
        }

        self.weights = WeightConfig.load(args.weights_json)

        # Identity index to reduce profile fragmentation
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.ip_to_id: Dict[str, str] = {}
        self.mac_to_id: Dict[str, str] = {}

        # Evidence dedup
        self.seen_hashes: Set[str] = set()

        # Optional analyzer
        self.imported_analyzer = ImportedCaptureAnalyzer(self.root_dir) if ImportedCaptureAnalyzer else None

        self.manifest: Dict[str, Any] = {
            "generated_at": int(time.time()),
            "root_dir": str(self.root_dir),
            "run_dir": str(self.run_dir),
            "logs_dir": str(self.logs_dir),
            "args": vars(args),
            "tools": self.tools,
            "stages": [],
            "saved_images": [],
        }
        self.saved_images: List[Dict[str, Any]] = []

    # -------------------------- identity / profiles --------------------------
    def _get_or_create_profile(self, *, ip: str = "", mac: str = "", hint: str = "") -> Dict[str, Any]:
        ip = (ip or "").strip()
        mac = (mac or "").strip().lower()

        if ip and ip in self.ip_to_id:
            return self.profiles[self.ip_to_id[ip]]
        if mac and mac in self.mac_to_id:
            return self.profiles[self.mac_to_id[mac]]

        profile_id = ip or mac or hint or f"unknown-{len(self.profiles)+1}"
        while profile_id in self.profiles:
            profile_id = f"{profile_id}-{len(self.profiles)+1}"

        profile = _empty_profile(profile_id)
        self.profiles[profile_id] = profile
        if ip and is_private_ip(ip):
            self.ip_to_id[ip] = profile_id
            profile["ips"].append(ip)
        if mac:
            self.mac_to_id[mac] = profile_id
            profile["macs"].append(mac)
        return profile

    def _merge_value(self, arr: List[str], v: str) -> None:
        v = (v or "").strip()
        if v and v not in arr:
            arr.append(v)

    def _add_source(self, profile: Dict[str, Any], source: str) -> None:
        self._merge_value(profile["passive"]["sources"], source)

    def _add_ip(self, profile: Dict[str, Any], ip: str) -> None:
        ip = (ip or "").strip()
        if ip and is_private_ip(ip):
            self._merge_value(profile["ips"], ip)
            self.ip_to_id[ip] = profile["device_id"]

    def _add_mac(self, profile: Dict[str, Any], mac: str) -> None:
        mac = (mac or "").strip().lower()
        if mac:
            self._merge_value(profile["macs"], mac)
            self.mac_to_id[mac] = profile["device_id"]

    def _add_hostname(self, profile: Dict[str, Any], hostname: str) -> None:
        hostname = (hostname or "").strip()
        if not hostname or hostname in {"<hidden>", "--"}:
            return
        self._merge_value(profile["hostnames"], hostname)
        h = hostname.lower()
        if any(t in h for t in IMAGING_HOSTNAME_KEYWORDS):
            self._merge_value(profile["passive"]["signals"], "imaging_hostname_hint")

    def _add_vendor(self, profile: Dict[str, Any], vendor: str) -> None:
        vendor = (vendor or "").strip()
        if not vendor:
            return
        self._merge_value(profile["vendors"], vendor)
        v = vendor.lower()
        if any(t in v for t in IMAGING_VENDOR_KEYWORDS):
            self._merge_value(profile["passive"]["signals"], "imaging_vendor_family")
        # camera vendor hints are a subset; keep it as a counter
        if any(t in v for t in ("hikvision", "dahua", "reolink", "axis", "vivotek", "hanwha", "wisenet", "uniview")):
            profile["passive"]["vendor_hints"] += 1

    def _add_domain(self, profile: Dict[str, Any], domain: str) -> None:
        domain = (domain or "").strip()
        if not domain:
            return
        self._merge_value(profile["domains"], domain)
        if any(t in domain.lower() for t in IMAGING_DOMAIN_KEYWORDS):
            self._merge_value(profile["passive"]["signals"], "imaging_domain_hint")

    # -------------------------- pcap selection --------------------------
    def _select_pcaps(self) -> List[Path]:
        pcaps: List[Path] = []
        if self.args.pcap:
            for item in self.args.pcap:
                p = Path(item).expanduser()
                if p.exists():
                    pcaps.append(p)
        if pcaps:
            return pcaps
        if self.logs_dir.exists():
            candidates = sorted(self.logs_dir.glob("*.pcap*"), key=lambda p: p.stat().st_mtime, reverse=True)
            return candidates[: max(1, int(self.args.pcap_limit))]
        return []

    # -------------------------- stages --------------------------
    def run(self) -> int:
        log(f"run_dir={self.run_dir}")
        pcaps = self._select_pcaps()
        if not pcaps:
            log("no pcaps selected; nothing to do")
            self._write_report()
            return 0

        # Stage: imported analyzer (if available)
        self._stage("imported_analyzer", lambda: self._run_imported_analyzer(pcaps))

        # Stage: tshark + zeek (parallel per pcap)
        self._stage("decode_pcaps", lambda: self._run_decode_pcaps(pcaps))

        # Stage: carving + media harvest
        self._stage("carving", lambda: self._run_carving(pcaps))

        # Stage: scoring
        self._stage("scoring", self._score_profiles)

        # Final report
        self._write_report()

        if self.args.enable_active_probes:
            log("ERROR: active probing is intentionally not implemented in this v2 script.")
            log("Implement an authorized ActiveProbePlugin in your environment if needed.")
            return 2

        return 0

    def _stage(self, name: str, fn: Any) -> None:
        started = time.time()
        ok = True
        err = ""
        try:
            fn()
        except Exception as exc:
            ok = False
            err = str(exc)
        self.manifest["stages"].append({
            "stage": name,
            "ok": ok,
            "error": err,
            "elapsed_seconds": round(time.time() - started, 2),
        })
        write_json(self.run_dir / f"stage_{name}.json", self.manifest["stages"][-1])

    # -------------------------- imported analyzer --------------------------
    def _run_imported_analyzer(self, pcaps: List[Path]) -> None:
        if not self.imported_analyzer:
            return
        for pcap in pcaps:
            analysis = self.imported_analyzer.analyze(str(pcap), replay=True)
            for collection_name in ("networks", "clients"):
                for item in analysis.get(collection_name) or []:
                    self._merge_from_imported_item(item, source=f"imported:{pcap.name}")

    def _merge_from_imported_item(self, item: Dict[str, Any], *, source: str) -> None:
        ip_hint = ""
        for ip_value in dict(item.get("destination_ip_counts") or {}):
            if is_private_ip(str(ip_value)):
                ip_hint = str(ip_value)
                break

        mac = str(item.get("bssid") or item.get("mac") or "").strip()
        profile = self._get_or_create_profile(ip=ip_hint, mac=mac, hint=str(item.get("record_id") or source))
        self._add_source(profile, source)

        self._add_mac(profile, mac)
        self._add_vendor(profile, str(item.get("vendor") or ""))
        self._add_hostname(profile, str(item.get("ssid") or item.get("hostname") or ""))

        camera_detection = dict(item.get("camera_detection") or {})
        if bool(camera_detection.get("detected")):
            self._merge_value(profile["passive"]["signals"], "camera_detection.detected")

        flow_metrics = dict(item.get("flow_metrics") or {})
        if bool(flow_metrics.get("long_lived_flow")):
            profile["passive"]["flow"]["long_lived_flow"] = True
            self._merge_value(profile["passive"]["signals"], "long_lived_flow")
        uplink_ratio = flow_metrics.get("uplink_ratio")
        if isinstance(uplink_ratio, (int, float)):
            profile["passive"]["flow"]["uplink_ratio"] = float(uplink_ratio)
            if float(uplink_ratio) >= 0.55:
                self._merge_value(profile["passive"]["signals"], "uplink_biased_traffic")

        for domain in dict(item.get("recurring_domain_profiles") or {}):
            self._add_domain(profile, str(domain))

        for ip_value in dict((item.get("stable_fingerprint") or {}).get("recurring_destination_ips") or {}):
            self._add_ip(profile, str(ip_value))

    # -------------------------- tshark/zeek decode --------------------------
    def _run_decode_pcaps(self, pcaps: List[Path]) -> None:
        tshark_dir = self.run_dir / "tshark"
        zeek_dir = self.run_dir / "zeek"
        tshark_dir.mkdir(parents=True, exist_ok=True)
        zeek_dir.mkdir(parents=True, exist_ok=True)

        def worker(pcap: Path) -> None:
            self._decode_one_pcap(pcap, tshark_dir, zeek_dir)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(self.args.max_workers))) as ex:
            list(ex.map(worker, pcaps))

    def _decode_one_pcap(self, pcap: Path, tshark_dir: Path, zeek_dir: Path) -> None:
        # tshark fields CSV
        if self.tools["tshark"]:
            csv_path = tshark_dir / f"{pcap.stem}_fields.csv"
            args = [
                self.tools["tshark"],
                "-r", str(pcap),
                "-T", "fields",
                "-E", "header=y",
                "-E", "separator=,",
                "-E", "quote=d",
            ]
            for field in DEFAULT_TSHARK_FIELDS:
                args += ["-e", field]
            res = run_command(args, timeout=int(self.args.tshark_timeout))
            csv_path.write_text(res.get("stdout") or "", encoding="utf-8")
            self._parse_tshark_csv(csv_path, source=f"tshark:{pcap.name}")

            # http object export
            export_dir = tshark_dir / f"{pcap.stem}_http_objects"
            export_dir.mkdir(parents=True, exist_ok=True)
            _ = run_command([self.tools["tshark"], "-r", str(pcap), "--export-objects", f"http,{export_dir}"], timeout=int(self.args.tshark_timeout))
            self._harvest_media(export_dir, source=f"http_export:{pcap.name}")

        # Zeek logs
        if self.tools["zeek"]:
            out = zeek_dir / pcap.stem
            out.mkdir(parents=True, exist_ok=True)
            _ = run_command([self.tools["zeek"], "-Cr", str(pcap), "LogAscii::use_json=T"], cwd=out, timeout=int(self.args.zeek_timeout))
            self._parse_zeek_logs(out, source=f"zeek:{pcap.name}")

    def _parse_tshark_csv(self, csv_path: Path, *, source: str) -> None:
        if not csv_path.exists():
            return

        with csv_path.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Two endpoints per row: process as bidirectional evidence.
                endpoints: List[Tuple[str, str]] = []
                for ip_field, mac_field in (("ip.src", "wlan.sa"), ("ip.dst", "wlan.da")):
                    endpoints.append((str(row.get(ip_field) or "").strip(), str(row.get(mac_field) or "").strip()))

                for ip_value, mac_value in endpoints:
                    profile = self._get_or_create_profile(ip=ip_value, mac=mac_value, hint=mac_value or ip_value or source)
                    self._add_source(profile, source)
                    self._add_ip(profile, ip_value)
                    self._add_mac(profile, mac_value)

                    # ports observed
                    for port_field in ("tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"):
                        p = str(row.get(port_field) or "").strip()
                        if p.isdigit():
                            port = int(p)
                            if port_field.endswith("dstport"):
                                if port not in profile["observed_server_ports"]:
                                    profile["observed_server_ports"].append(port)
                            else:
                                if port not in profile["observed_client_ports"]:
                                    profile["observed_client_ports"].append(port)

                    # hostname / vendor class
                    self._add_hostname(profile, str(row.get("bootp.option.hostname") or ""))
                    self._add_vendor(profile, str(row.get("bootp.option.vendor_class_id") or ""))

                    # domains + TLS SNI + HTTP host
                    for dfield in ("dns.qry.name", "dns.resp.name", "http.host", "tls.handshake.extensions_server_name"):
                        self._add_domain(profile, str(row.get(dfield) or ""))

                    # HTTP surface tokens (passive)
                    uri = str(row.get("http.request.uri") or "").strip().lower()
                    server = str(row.get("http.server") or "").strip().lower()
                    if uri:
                        if any(tok in uri for tok in ("snapshot", "onvif", "stream", "isapi")):
                            profile["passive"]["http_cam_surface_seen"] += 1
                            self._merge_value(profile["passive"]["signals"], "http_camera_surface_token")
                    if server:
                        # Keep as weak evidence: server banners can be shared by many embedded stacks.
                        if any(tok in server for tok in ("camera", "onvif", "rtsp")):
                            profile["passive"]["http_cam_surface_seen"] += 1
                            self._merge_value(profile["passive"]["signals"], "http_server_banner_cameraish")

                    # RTSP evidence
                    if str(row.get("rtsp.method") or "").strip() or str(row.get("rtsp.url") or "").strip():
                        profile["passive"]["rtsp_seen"] += 1
                        self._merge_value(profile["passive"]["signals"], "rtsp_seen")

    def _parse_zeek_logs(self, zeek_dir: Path, *, source: str) -> None:
        # Parse only JSON Zeek logs if present
        for name in ("conn.log", "dns.log", "http.log", "ssl.log", "x509.log", "dhcp.log", "files.log"):
            path = zeek_dir / name
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    orig = str(rec.get("id.orig_h") or "").strip()
                    resp = str(rec.get("id.resp_h") or "").strip()

                    # Prefer private IP endpoints for profile association
                    chosen_ip = orig if is_private_ip(orig) else (resp if is_private_ip(resp) else "")
                    profile = self._get_or_create_profile(ip=chosen_ip, hint=chosen_ip or source)
                    self._add_source(profile, source)
                    self._add_ip(profile, orig)
                    self._add_ip(profile, resp)

                    # conn.log flow behavior
                    if name == "conn.log":
                        duration = rec.get("duration")
                        if isinstance(duration, (int, float)) and float(duration) >= float(self.args.long_flow_seconds):
                            profile["passive"]["flow"]["long_lived_flow"] = True
                            self._merge_value(profile["passive"]["signals"], "long_lived_flow")
                        resp_p = rec.get("id.resp_p")
                        if isinstance(resp_p, int):
                            if resp_p not in profile["observed_server_ports"]:
                                profile["observed_server_ports"].append(resp_p)

                        # uplink bias approximation using bytes if present
                        ob = rec.get("orig_bytes")
                        rb = rec.get("resp_bytes")
                        if isinstance(ob, (int, float)) and isinstance(rb, (int, float)) and (ob + rb) > 0:
                            ratio = float(ob) / float(ob + rb)
                            profile["passive"]["flow"]["uplink_ratio"] = ratio
                            if ratio >= 0.55:
                                self._merge_value(profile["passive"]["signals"], "uplink_biased_traffic")

                    # dns.log domains
                    if name == "dns.log":
                        self._add_domain(profile, str(rec.get("query") or ""))

                    # http.log host + uri behavior
                    if name == "http.log":
                        self._add_domain(profile, str(rec.get("host") or ""))
                        uri = str(rec.get("uri") or "").lower()
                        if any(tok in uri for tok in ("snapshot", "onvif", "stream", "isapi")):
                            profile["passive"]["http_cam_surface_seen"] += 1
                            self._merge_value(profile["passive"]["signals"], "http_camera_surface_token")

                    # ssl.log server_name
                    if name == "ssl.log":
                        self._add_domain(profile, str(rec.get("server_name") or ""))

                    # x509.log subject/issuer/san_dns as family-like hints
                    if name == "x509.log":
                        for field in ("subject", "issuer"):
                            v = rec.get(field)
                            if isinstance(v, str) and v:
                                self._merge_value(profile["vendors"], v)
                        san = rec.get("san_dns")
                        if isinstance(san, list):
                            for d in san:
                                if isinstance(d, str):
                                    self._add_domain(profile, d)

                    # dhcp.log host_name + domain
                    if name == "dhcp.log":
                        self._add_hostname(profile, str(rec.get("host_name") or ""))
                        self._add_domain(profile, str(rec.get("domain") or ""))

    # -------------------------- carving & media --------------------------
    def _run_carving(self, pcaps: List[Path]) -> None:
        carve_dir = self.run_dir / "carving"
        carve_dir.mkdir(parents=True, exist_ok=True)

        for pcap in pcaps:
            if self.tools["foremost"]:
                target = carve_dir / f"{pcap.stem}_foremost"
                _ = run_command([self.tools["foremost"], "-i", str(pcap), "-o", str(target)], timeout=int(self.args.carve_timeout))
                self._harvest_media(target, source=f"foremost:{pcap.name}")
            if self.tools["tcpflow"]:
                target = carve_dir / f"{pcap.stem}_tcpflow"
                target.mkdir(parents=True, exist_ok=True)
                _ = run_command([self.tools["tcpflow"], "-r", str(pcap), "-o", str(target)], timeout=int(self.args.carve_timeout))
                self._harvest_media(target, source=f"tcpflow:{pcap.name}")

    def _harvest_media(self, source_dir: Path, *, source: str) -> None:
        if not source_dir.exists():
            return
        max_bytes = int(self.args.max_candidate_file_mb) * 1024 * 1024
        for p in source_dir.rglob("*"):
            if not p.is_file():
                continue
            if p.stat().st_size <= 0 or p.stat().st_size > max_bytes:
                continue
            meta = self._validate_and_copy_image(p, source=source)
            if meta.get("copied_path"):
                self.saved_images.append(meta)
                self.manifest["saved_images"].append(meta)

    def _detect_mime(self, path: Path) -> str:
        if self.tools["file"]:
            res = run_command([self.tools["file"], "--brief", "--mime-type", str(path)], timeout=15)
            return str(res.get("stdout") or "").strip()
        # fallback: extension guess
        return {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".bmp": "image/bmp",
        }.get(path.suffix.lower(), "")

    def _validate_and_copy_image(self, path: Path, *, source: str) -> Dict[str, Any]:
        mime = self._detect_mime(path)
        is_image = mime.startswith("image/") or path.suffix.lower() in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
        meta: Dict[str, Any] = {
            "source": source,
            "original_path": str(path),
            "mime_type": mime,
            "sha256": "",
            "copied_path": "",
            "exif": None,
        }
        if not is_image:
            return meta

        digest = sha256_file(path)
        meta["sha256"] = digest
        if digest in self.seen_hashes:
            return meta
        self.seen_hashes.add(digest)

        self.image_dir.mkdir(parents=True, exist_ok=True)
        target = self.image_dir / f"{now_ts()}_{safe_name(path.name)}"
        suffix = 1
        while target.exists():
            target = self.image_dir / f"{now_ts()}_{suffix}_{safe_name(path.name)}"
            suffix += 1

        try:
            shutil.copy2(path, target)
            meta["copied_path"] = str(target)
        except OSError:
            return meta

        # Optional EXIF capture
        if self.tools["exiftool"]:
            ex = run_command([self.tools["exiftool"], "-json", str(target)], timeout=30)
            if ex.get("ok") and ex.get("stdout"):
                try:
                    meta["exif"] = json.loads(ex["stdout"])[0]
                except Exception:
                    meta["exif"] = None

        # Sidecar provenance
        sidecar = target.with_suffix(target.suffix + ".json")
        write_json(sidecar, meta)
        return meta

    # -------------------------- scoring --------------------------
    def _score_profiles(self) -> None:
        w = self.weights

        for p in self.profiles.values():
            signals = set(p["passive"]["signals"])
            reasons: List[str] = []
            missing: List[str] = []

            camera_score = 0.0
            imaging_score = 0.0

            # Camera protocol evidence (passive)
            if p["passive"]["rtsp_seen"] > 0 or "rtsp_seen" in signals:
                camera_score += w.w_rtsp_seen
                imaging_score += w.w_rtsp_seen * 0.6
                reasons.append("RTSP observed in passive traffic")
            else:
                missing.append("RTSP traffic")

            # Web-surface evidence (passive)
            if p["passive"]["http_cam_surface_seen"] > 0 or "http_camera_surface_token" in signals:
                camera_score += w.w_http_cam_surface
                imaging_score += w.w_http_cam_surface * 0.7
                reasons.append("Camera-like HTTP surface tokens observed")
            else:
                missing.append("camera-like HTTP surface")

            # Vendor hints
            if p["passive"]["vendor_hints"] > 0:
                bonus = min(15.0, w.w_camera_vendor * float(p["passive"]["vendor_hints"]))
                camera_score += bonus
                imaging_score += bonus
                reasons.append("Vendor hints match common camera families")
            else:
                missing.append("camera-family vendor hint")

            # Flow behavior
            if "long_lived_flow" in signals or bool(p["passive"]["flow"].get("long_lived_flow")):
                camera_score += w.w_long_lived_flow
                imaging_score += w.w_long_lived_flow * 0.7
                reasons.append("Long-lived flow behavior")
            if "uplink_biased_traffic" in signals:
                camera_score += w.w_uplink_bias
                imaging_score += w.w_uplink_bias * 0.8
                reasons.append("Uplink-biased traffic pattern")

            # Imaging-capable inference
            if "imaging_vendor_family" in signals:
                imaging_score += w.w_imaging_vendor
                reasons.append("Imaging-capable vendor ecosystem")
            if "imaging_hostname_hint" in signals:
                imaging_score += w.w_imaging_hostname
                reasons.append("Hostname suggests imaging-capable device")
            if "imaging_domain_hint" in signals:
                imaging_score += w.w_imaging_domain
                reasons.append("Domain activity suggests imaging/video stack")

            # Dampening: if we have almost no passive evidence, reduce confidence
            evidence_count = (
                int(p["passive"]["rtsp_seen"] > 0)
                + int(p["passive"]["http_cam_surface_seen"] > 0)
                + int(p["passive"]["vendor_hints"] > 0)
                + int("imaging_domain_hint" in signals)
            )
            if evidence_count <= 1:
                camera_score = max(0.0, camera_score - w.penalty_low_evidence)
                imaging_score = max(0.0, imaging_score - w.penalty_low_evidence * 0.6)

            # Tiering
            tier = "LOW"
            if camera_score >= w.high_threshold or imaging_score >= w.high_threshold:
                tier = "HIGH"
            elif camera_score >= w.medium_threshold or imaging_score >= w.medium_threshold:
                tier = "MEDIUM"

            # Hypothesis
            vendors_blob = " ".join(p["vendors"]).lower()
            host_blob = " ".join(p["hostnames"]).lower()

            likely_type = "unknown"
            if camera_score >= w.medium_threshold:
                likely_type = "camera_or_video_endpoint"
            elif any(t in host_blob for t in ("doorbell", "ring")):
                likely_type = "doorbell_or_entry_cam"
            elif any(t in host_blob for t in ("pet", "baby", "monitor")):
                likely_type = "monitoring_device"
            elif any(t in vendors_blob for t in ("apple", "samsung", "google", "xiaomi", "oneplus", "oppo", "vivo", "huawei")):
                likely_type = "phone_or_tablet_with_camera"
            elif any(t in vendors_blob for t in ("dell", "hp", "lenovo", "asus", "acer", "microsoft", "msi")):
                likely_type = "computer_with_webcam"
            elif "imaging_vendor_family" in signals:
                likely_type = "imaging_capable_iot_device"

            imaging_capable = imaging_score >= 20.0 or bool({"imaging_vendor_family", "imaging_hostname_hint", "imaging_domain_hint"} & signals)

            p["confidence"]["camera_score"] = round(min(camera_score, 100.0), 1)
            p["confidence"]["imaging_score"] = round(min(imaging_score, 100.0), 1)
            p["confidence"]["tier"] = tier
            p["confidence"]["reasons"] = reasons[:10]
            p["confidence"]["missing_evidence"] = sorted(set(missing))

            p["device_hypothesis"] = {
                "likely_type": likely_type,
                "imaging_capable": imaging_capable,
                "camera_specific": p["confidence"]["camera_score"] >= w.medium_threshold,
                "reasons": reasons[:10],
            }

            ips = ", ".join(p["ips"][:2]) or "no IP"
            vendors = ", ".join(p["vendors"][:2]) or "unknown vendor"
            p["report_summary"] = f"{ips} | {vendors} | camera {p['confidence']['camera_score']:.1f} | imaging {p['confidence']['imaging_score']:.1f} | {likely_type}"

    # -------------------------- reporting --------------------------
    def _write_report(self) -> None:
        profiles = sorted(
            self.profiles.values(),
            key=lambda x: (x["confidence"]["camera_score"], x["confidence"]["imaging_score"], len(x["domains"]), len(x["ips"])),
            reverse=True,
        )
        report = {
            "generated_at": int(time.time()),
            "run_dir": str(self.run_dir),
            "image_dir": str(self.image_dir),
            "summary": {
                "profile_count": len(profiles),
                "high": sum(1 for p in profiles if p["confidence"]["tier"] == "HIGH"),
                "medium": sum(1 for p in profiles if p["confidence"]["tier"] == "MEDIUM"),
                "saved_image_count": len(self.saved_images),
            },
            "top_targets": profiles[: min(10, len(profiles))],
            "profiles": profiles,
            "saved_images": self.saved_images,
            "manifest": self.manifest,
        }
        write_json(self.run_dir / "intelligence_report.json", report)
        write_json(self.run_dir / "run_manifest.json", self.manifest)
        log(f"profiles={len(profiles)} saved_images={len(self.saved_images)}")

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GhostReconCameraHunt v2 (passive-first upgrade)")
    p.add_argument("--pcap", action="append", default=[], help="pcap/pcapng files to analyze (repeatable)")
    p.add_argument("--pcap-limit", type=int, default=8, help="how many recent pcaps from logs_dir to analyze")
    p.add_argument("--logs-dir", default="", help="defaults to repo logs/wifi_mk7 if empty")
    p.add_argument("--weights-json", default="", help="optional JSON file overriding scoring weights/thresholds")
    p.add_argument("--max-workers", type=int, default=4, help="parallel workers for pcap decode")
    p.add_argument("--tshark-timeout", type=int, default=240, help="seconds per tshark stage")
    p.add_argument("--zeek-timeout", type=int, default=360, help="seconds per zeek stage")
    p.add_argument("--carve-timeout", type=int, default=360, help="seconds per carving tool run")
    p.add_argument("--max-candidate-file-mb", type=int, default=8, help="skip carved files larger than this")
    p.add_argument("--long-flow-seconds", type=float, default=20.0, help="conn duration threshold to classify long-lived flows")
    p.add_argument("--enable-active-probes", action="store_true", help="not implemented in v2; reserved for authorized plugin")
    return p

def main() -> int:
    args = build_parser().parse_args()
    runner = GhostReconCameraHuntV2(args)
    return runner.run()

if __name__ == "__main__":
    raise SystemExit(main())
