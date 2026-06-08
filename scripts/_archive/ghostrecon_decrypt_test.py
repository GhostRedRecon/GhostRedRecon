#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}
EXPORT_OBJECT_TYPES = ("http", "ftp-data", "imf", "smb", "tftp", "x509af")
CAMERA_HINT_KEYWORDS = (
    "onvif",
    "rtsp",
    "snapshot",
    "mjpeg",
    "mjpg",
    "isapi",
    "cgi-bin",
    "hikvision",
    "dahua",
    "reolink",
    "amcrest",
    "foscam",
    "axis",
    "vivotek",
    "wyze",
    "arlo",
    "ring",
    "nest",
    "eufy",
    "tapo",
    "camera",
    "doorbell",
)
FIELD_NAMES = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    "wlan.sa",
    "wlan.da",
    "wlan.bssid",
    "wlan.fc.type_subtype",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "udp.port",
    "eapol.type",
    "wlan_rsna_eapol.keydes.msgnr",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.full_uri",
    "http.content_type",
    "http.user_agent",
    "http.server",
    "http.authorization",
    "http.response.code",
    "http.location",
    "http.www_authenticate",
    "tls.handshake.extensions_server_name",
    "tls.handshake.type",
    "tls.record.content_type",
    "x509ce.dNSName",
    "dns.qry.name",
    "dns.resp.name",
    "dhcp.option.hostname",
    "xml.tag",
    "xml.attribute",
    "rtsp.method",
    "rtsp.url",
    "rtsp.content-type",
    "rtsp.transport",
    "rtsp.response",
    "rtsp.content-base",
)
COUNT_FILTERS = (
    ("total_frames", ""),
    ("data_frames", "wlan.fc.type == 2"),
    ("eapol_frames", "eapol"),
    ("ip_frames", "ip || ipv6"),
    ("arp_frames", "arp"),
    ("http_frames", "http"),
    ("tls_frames", "tls"),
    ("dns_frames", "dns"),
    ("dhcp_frames", "dhcp"),
    ("rtsp_frames", "rtsp"),
)


def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def log(message: str) -> None:
    print(f"[decrypt-test] {message}", flush=True)


def tool(name: str) -> str:
    return shutil.which(name) or ""


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_command(args: List[str], *, timeout: int = 300, cwd: Path | None = None) -> Dict[str, Any]:
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


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        return list(csv.DictReader(handle))


def unique_sorted(values: Iterable[str], *, limit: int = 20) -> List[str]:
    normalized = sorted({str(value).strip() for value in values if str(value).strip()})
    return normalized[:limit]


def keyword_hits(values: Iterable[str]) -> List[str]:
    hits: List[str] = []
    for value in values:
        lowered = str(value or "").lower()
        if any(keyword in lowered for keyword in CAMERA_HINT_KEYWORDS):
            hits.append(str(value))
    return unique_sorted(hits, limit=25)


def safe_label(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)


def coalesce_endpoint(row: Dict[str, str], prefix: str) -> str:
    for key in (f"ip.{prefix}", f"ipv6.{prefix}"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


class GhostReconDecryptTest:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root_dir = REPO_ROOT
        self.run_dir = self.root_dir / "evidence" / "decrypt_test_runs" / now_ts()
        self.image_dir = self.root_dir / "evidence" / "camera_images"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.tools = {
            "tshark": tool("tshark"),
            "file": tool("file"),
        }
        self.export_object_types = self._detect_export_object_types()
        self.saved_images: List[str] = []
        self.warnings: List[str] = []
        self.key_warnings: List[str] = []

    def run(self) -> int:
        if not self.tools["tshark"]:
            raise SystemExit("tshark is required")
        pcaps = self._pcaps()
        report: Dict[str, Any] = {
            "generated_at": int(time.time()),
            "run_dir": str(self.run_dir),
            "authorized_inputs": self._authorized_input_summary(),
            "warnings": self.warnings,
            "available_tools": self.tools,
            "export_object_types": self.export_object_types,
            "pcaps": [],
            "saved_images": [],
        }
        if not pcaps:
            report["warnings"].append("no_pcaps_found")
        for pcap in pcaps:
            report["pcaps"].append(self._analyze_pcap(pcap))
        report["saved_images"] = self.saved_images
        write_json(self.run_dir / "decrypt_report.json", report)
        write_text(self.run_dir / "decrypt_summary.txt", self._render_summary(report))
        log(f"run directory: {self.run_dir}")
        log(f"pcaps analyzed: {len(report['pcaps'])}")
        log(f"saved images: {len(self.saved_images)}")
        return 0

    def _authorized_input_summary(self) -> Dict[str, Any]:
        wifi_key_ssids: List[str] = []
        wifi_psk_ssids: List[str] = []
        for item in self.args.wifi_key:
            ssid, ok = self._parse_authorized_key(item, key_type="wpa-pwd")
            if ok:
                wifi_key_ssids.append(ssid)
        for item in self.args.wifi_psk:
            ssid, ok = self._parse_authorized_key(item, key_type="wpa-psk")
            if ok:
                wifi_psk_ssids.append(ssid)
        summary = {
            "wifi_key_count": len(wifi_key_ssids),
            "wifi_key_ssids": unique_sorted(wifi_key_ssids, limit=64),
            "wifi_psk_count": len(wifi_psk_ssids),
            "wifi_psk_ssids": unique_sorted(wifi_psk_ssids, limit=64),
            "tls_keylog_supplied": bool(self.args.tls_keylog),
            "tls_keylog_path": str(Path(self.args.tls_keylog).expanduser()) if self.args.tls_keylog else "",
            "key_warnings": self.key_warnings,
        }
        return summary

    def _parse_authorized_key(self, raw: str, *, key_type: str) -> Tuple[str, bool]:
        self._parse_authorized_key_once(raw, key_type=key_type)
        if ":" not in raw:
            return "", False
        ssid, secret = raw.split(":", 1)
        ssid = ssid.strip()
        secret = secret.strip()
        return ssid, bool(ssid and secret)

    def _parse_authorized_key_once(self, raw: str, *, key_type: str) -> None:
        if ":" not in raw:
            warning = f"ignored malformed {key_type} entry without SSID separator"
            if warning not in self.key_warnings:
                self.key_warnings.append(warning)
            return
        ssid, secret = raw.split(":", 1)
        ssid = ssid.strip()
        secret = secret.strip()
        if not ssid or not secret:
            warning = f"ignored malformed {key_type} entry with empty SSID or secret"
            if warning not in self.key_warnings:
                self.key_warnings.append(warning)
            return

    def _pcaps(self) -> List[Path]:
        if self.args.pcap:
            selected = [Path(item).expanduser() for item in self.args.pcap]
            return [item for item in selected if item.exists() and item.is_file()]
        logs_dir = self.root_dir / "logs" / "wifi_mk7"
        return sorted(logs_dir.glob("*.pcap*"), key=lambda item: item.stat().st_mtime, reverse=True)[: max(1, int(self.args.pcap_limit))]

    def _detect_export_object_types(self) -> List[str]:
        if not self.tools["tshark"]:
            return ["http"]
        result = run_command([self.tools["tshark"], "--export-objects", "help"], timeout=30)
        available: List[str] = []
        help_text = "\n".join(
            part for part in (str(result.get("stdout") or ""), str(result.get("stderr") or "")) if part
        )
        for line in help_text.splitlines():
            value = line.strip()
            if value and value in EXPORT_OBJECT_TYPES:
                available.append(value)
        return available or ["http"]

    def _tshark_base(self, pcap: Path) -> List[str]:
        cmd = [
            self.tools["tshark"],
            "-2",
            "-r",
            str(pcap),
            "-o",
            "wlan.enable_decryption:TRUE",
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
            "-o",
            "http.desegment_body:TRUE",
        ]
        if self.args.tls_keylog:
            cmd.extend(["-o", f"tls.keylog_file:{Path(self.args.tls_keylog).expanduser()}"])
        for item in self.args.wifi_key:
            ssid, ok = self._parse_authorized_key(item, key_type="wpa-pwd")
            if ok:
                cmd.extend(["-o", f'uat:80211_keys:"wpa-pwd","{item.strip()}"'])
        for item in self.args.wifi_psk:
            ssid, ok = self._parse_authorized_key(item, key_type="wpa-psk")
            if ok and ssid:
                cmd.extend(["-o", f'uat:80211_keys:"wpa-psk","{item.strip()}"'])
        return cmd

    def _analyze_pcap(self, pcap: Path) -> Dict[str, Any]:
        log(f"analyzing {pcap.name}")
        pcap_dir = self.run_dir / safe_label(pcap.stem)
        pcap_dir.mkdir(parents=True, exist_ok=True)

        fields_csv = pcap_dir / "analyst_fields.csv"
        fields_result = self._extract_fields(pcap, fields_csv)
        rows = read_csv_rows(fields_csv)
        object_exports, object_images = self._export_objects(pcap, pcap_dir)
        handshake = self._handshake_summary(pcap)
        counts = self._protocol_counts(pcap)
        summary = self._summarize_rows(rows, counts=counts, handshake=handshake)
        findings = self._derive_findings(summary)

        pcap_report = {
            "pcap": str(pcap),
            "field_extract": {k: v for k, v in fields_result.items() if k != "stdout"},
            "field_csv": str(fields_csv),
            "object_exports": object_exports,
            "summary": summary,
            "findings": findings,
            "saved_images": object_images,
        }
        write_text(pcap_dir / "summary.txt", self._render_pcap_summary(pcap_report))
        return pcap_report

    def _extract_fields(self, pcap: Path, output_path: Path) -> Dict[str, Any]:
        cmd = self._tshark_base(pcap) + [
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
        ]
        for field in FIELD_NAMES:
            cmd.extend(["-e", field])
        result = run_command(cmd, timeout=self.args.timeout)
        output_path.write_text(str(result.get("stdout") or ""), encoding="utf-8")
        return result

    def _export_objects(self, pcap: Path, pcap_dir: Path) -> Tuple[Dict[str, Any], List[str]]:
        exports: Dict[str, Any] = {}
        images: List[str] = []
        for object_type in self.export_object_types:
            export_dir = pcap_dir / f"{object_type}_objects"
            export_dir.mkdir(parents=True, exist_ok=True)
            result = run_command(
                self._tshark_base(pcap) + ["--export-objects", f"{object_type},{export_dir}"],
                timeout=self.args.timeout,
            )
            exported_files = sorted(str(item) for item in export_dir.rglob("*") if item.is_file())
            exports[object_type] = {
                **{k: v for k, v in result.items() if k != "stdout"},
                "export_dir": str(export_dir),
                "file_count": len(exported_files),
                "files": exported_files[:50],
            }
            images.extend(self._collect_images(export_dir, source=pcap.name, object_type=object_type))
        return exports, images

    def _protocol_counts(self, pcap: Path) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for label, display_filter in COUNT_FILTERS:
            cmd = self._tshark_base(pcap) + ["-T", "fields", "-e", "frame.number"]
            if display_filter:
                cmd.extend(["-Y", display_filter])
            result = run_command(cmd, timeout=self.args.timeout)
            counts[label] = len([line for line in str(result.get("stdout") or "").splitlines() if line.strip()])
        return counts

    def _handshake_summary(self, pcap: Path) -> Dict[str, Any]:
        cmd = self._tshark_base(pcap) + [
            "-Y",
            "eapol",
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-e",
            "frame.number",
            "-e",
            "wlan.sa",
            "-e",
            "wlan.da",
            "-e",
            "wlan_rsna_eapol.keydes.msgnr",
            "-e",
            "eapol.keydes.replay_counter",
        ]
        result = run_command(cmd, timeout=self.args.timeout)
        csv_path = self.run_dir / f"{safe_label(pcap.stem)}_handshakes.csv"
        csv_path.write_text(str(result.get("stdout") or ""), encoding="utf-8")
        rows = read_csv_rows(csv_path)
        pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in rows:
            sa = str(row.get("wlan.sa") or "").strip()
            da = str(row.get("wlan.da") or "").strip()
            if not sa and not da:
                continue
            pair_key = tuple(sorted([sa, da]))
            if pair_key not in pairs:
                pairs[pair_key] = {
                    "station_a": pair_key[0],
                    "station_b": pair_key[1],
                    "messages_seen": set(),
                    "frame_numbers": [],
                    "replay_counters": set(),
                }
            pair = pairs[pair_key]
            message_numbers = str(row.get("wlan_rsna_eapol.keydes.msgnr") or "").replace(";", ",").split(",")
            for message_number in message_numbers:
                if message_number.strip().isdigit():
                    pair["messages_seen"].add(int(message_number.strip()))
            frame_number = str(row.get("frame.number") or "").strip()
            if frame_number:
                pair["frame_numbers"].append(frame_number)
            replay_counter = str(row.get("eapol.keydes.replay_counter") or "").strip()
            if replay_counter:
                pair["replay_counters"].add(replay_counter)
        summary_pairs: List[Dict[str, Any]] = []
        for pair in pairs.values():
            messages_seen = sorted(pair["messages_seen"])
            summary_pairs.append(
                {
                    "station_a": pair["station_a"],
                    "station_b": pair["station_b"],
                    "messages_seen": messages_seen,
                    "complete_handshake": messages_seen == [1, 2, 3, 4],
                    "frame_numbers": pair["frame_numbers"][:20],
                    "replay_counter_count": len(pair["replay_counters"]),
                }
            )
        return {
            "eapol_frame_count": len(rows),
            "pairs": summary_pairs,
            "complete_pair_count": sum(1 for pair in summary_pairs if pair["complete_handshake"]),
        }

    def _summarize_rows(self, rows: List[Dict[str, str]], *, counts: Dict[str, int], handshake: Dict[str, Any]) -> Dict[str, Any]:
        http_hosts = unique_sorted(row.get("http.host", "") for row in rows)
        http_uris = unique_sorted(
            value
            for row in rows
            for value in (row.get("http.request.full_uri", ""), row.get("http.request.uri", ""))
        )
        tls_sni = unique_sorted(row.get("tls.handshake.extensions_server_name", "") for row in rows)
        dns_names = unique_sorted(
            value
            for row in rows
            for value in (row.get("dns.qry.name", ""), row.get("dns.resp.name", ""))
        )
        dhcp_hostnames = unique_sorted(row.get("dhcp.option.hostname", "") for row in rows)
        rtsp_urls = unique_sorted(row.get("rtsp.url", "") for row in rows)
        rtsp_transports = unique_sorted(row.get("rtsp.transport", "") for row in rows)
        rtsp_content_bases = unique_sorted(row.get("rtsp.content-base", "") for row in rows)
        certificate_names = unique_sorted(row.get("x509ce.dNSName", "") for row in rows)
        http_user_agents = unique_sorted(row.get("http.user_agent", "") for row in rows)
        http_servers = unique_sorted(row.get("http.server", "") for row in rows)
        http_locations = unique_sorted(row.get("http.location", "") for row in rows)
        http_auth_challenges = unique_sorted(row.get("http.www_authenticate", "") for row in rows)
        xml_tags = unique_sorted((row.get("xml.tag", "") for row in rows), limit=50)
        xml_attributes = unique_sorted((row.get("xml.attribute", "") for row in rows), limit=50)
        protocol_values = unique_sorted((row.get("frame.protocols", "") for row in rows), limit=50)

        endpoint_counter: Counter[str] = Counter()
        credential_frames = 0
        for row in rows:
            for key in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"):
                value = str(row.get(key) or "").strip()
                if value:
                    endpoint_counter[value] += 1
            if str(row.get("http.authorization") or "").strip():
                credential_frames += 1

        camera_indicators = keyword_hits(
            list(http_hosts)
            + list(http_uris)
            + list(http_locations)
            + list(http_auth_challenges)
            + list(tls_sni)
            + list(dns_names)
            + list(dhcp_hostnames)
            + list(rtsp_urls)
            + list(rtsp_content_bases)
            + list(rtsp_transports)
            + list(certificate_names)
            + list(xml_tags)
            + list(xml_attributes)
        )
        top_endpoints = [value for value, _ in endpoint_counter.most_common(20)]
        device_leads = self._build_device_leads(rows)
        ws_discovery_frames = sum(
            1
            for row in rows
            if str(row.get("udp.port") or "").strip() == "3702"
            or "wsdd" in str(row.get("frame.protocols") or "").lower()
            or any(token in str(row.get("xml.tag") or "").lower() for token in ("probe", "probematches", "scopes", "xaddr", "types"))
        )
        ssdp_frames = sum(
            1
            for row in rows
            if str(row.get("udp.port") or "").strip() == "1900"
            or "ssdp" in str(row.get("frame.protocols") or "").lower()
        )

        decryption_attempted = bool(self.args.wifi_key or self.args.wifi_psk or self.args.tls_keylog)
        likely_decrypted_payload = counts.get("ip_frames", 0) > 0 or counts.get("http_frames", 0) > 0 or counts.get("tls_frames", 0) > 0 or counts.get("rtsp_frames", 0) > 0
        likely_decryption_success = decryption_attempted and likely_decrypted_payload
        likely_missing_wifi_handshake = (
            bool(self.args.wifi_key or self.args.wifi_psk)
            and handshake.get("eapol_frame_count", 0) > 0
            and handshake.get("complete_pair_count", 0) == 0
            and not likely_decrypted_payload
        )

        return {
            "row_count": len(rows),
            "protocol_counts": counts,
            "protocol_samples": protocol_values,
            "top_endpoints": top_endpoints,
            "http_hosts": http_hosts,
            "http_uris": http_uris[:25],
            "http_user_agents": http_user_agents,
            "http_servers": http_servers,
            "http_locations": http_locations,
            "http_auth_challenges": http_auth_challenges,
            "http_authorization_frames": credential_frames,
            "tls_sni": tls_sni,
            "certificate_names": certificate_names,
            "dns_names": dns_names,
            "dhcp_hostnames": dhcp_hostnames,
            "rtsp_urls": rtsp_urls,
            "rtsp_transports": rtsp_transports,
            "rtsp_content_bases": rtsp_content_bases,
            "xml_tags": xml_tags,
            "xml_attributes": xml_attributes,
            "camera_indicators": camera_indicators,
            "ws_discovery_frames": ws_discovery_frames,
            "ssdp_frames": ssdp_frames,
            "device_leads": device_leads,
            "handshake": handshake,
            "decryption_attempted": decryption_attempted,
            "likely_decrypted_payload": likely_decrypted_payload,
            "likely_decryption_success": likely_decryption_success,
            "likely_missing_wifi_handshake": likely_missing_wifi_handshake,
        }

    def _build_device_leads(self, rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        leads: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            dst = coalesce_endpoint(row, "dst")
            src = coalesce_endpoint(row, "src")
            endpoint = dst or src
            if not endpoint:
                continue
            lead = leads.setdefault(
                endpoint,
                {
                    "endpoint": endpoint,
                    "score": 0,
                    "protocols": set(),
                    "ports": set(),
                    "http_hosts": set(),
                    "http_uris": set(),
                    "tls_sni": set(),
                    "dns_names": set(),
                    "dhcp_hostnames": set(),
                    "rtsp_urls": set(),
                    "xml_tags": set(),
                    "camera_evidence": [],
                },
            )
            protocol_text = str(row.get("frame.protocols") or "").strip()
            if protocol_text:
                lead["protocols"].add(protocol_text)
            for key in ("tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "udp.port"):
                value = str(row.get(key) or "").strip()
                if value:
                    lead["ports"].add(value)
            for field_name, target_key in (
                ("http.host", "http_hosts"),
                ("http.request.full_uri", "http_uris"),
                ("http.request.uri", "http_uris"),
                ("tls.handshake.extensions_server_name", "tls_sni"),
                ("dns.qry.name", "dns_names"),
                ("dns.resp.name", "dns_names"),
                ("dhcp.option.hostname", "dhcp_hostnames"),
                ("rtsp.url", "rtsp_urls"),
                ("xml.tag", "xml_tags"),
            ):
                value = str(row.get(field_name) or "").strip()
                if value:
                    lead[target_key].add(value)
            score_delta, evidence = self._score_device_row(row)
            lead["score"] += score_delta
            for item in evidence:
                if item not in lead["camera_evidence"]:
                    lead["camera_evidence"].append(item)

        ranked: List[Dict[str, Any]] = []
        for lead in leads.values():
            if lead["score"] <= 0 and not lead["camera_evidence"]:
                continue
            ranked.append(
                {
                    "endpoint": lead["endpoint"],
                    "score": lead["score"],
                    "protocols": sorted(lead["protocols"])[:10],
                    "ports": sorted(lead["ports"], key=lambda item: int(item) if item.isdigit() else item)[:20],
                    "http_hosts": sorted(lead["http_hosts"])[:10],
                    "http_uris": sorted(lead["http_uris"])[:10],
                    "tls_sni": sorted(lead["tls_sni"])[:10],
                    "dns_names": sorted(lead["dns_names"])[:10],
                    "dhcp_hostnames": sorted(lead["dhcp_hostnames"])[:10],
                    "rtsp_urls": sorted(lead["rtsp_urls"])[:10],
                    "xml_tags": sorted(lead["xml_tags"])[:10],
                    "camera_evidence": lead["camera_evidence"][:20],
                }
            )
        ranked.sort(key=lambda item: (-int(item["score"]), item["endpoint"]))
        return ranked[:20]

    def _score_device_row(self, row: Dict[str, str]) -> Tuple[int, List[str]]:
        score = 0
        evidence: List[str] = []

        combined_values = [
            str(row.get("http.host") or ""),
            str(row.get("http.request.full_uri") or ""),
            str(row.get("http.request.uri") or ""),
            str(row.get("http.location") or ""),
            str(row.get("http.www_authenticate") or ""),
            str(row.get("tls.handshake.extensions_server_name") or ""),
            str(row.get("dns.qry.name") or ""),
            str(row.get("dns.resp.name") or ""),
            str(row.get("dhcp.option.hostname") or ""),
            str(row.get("rtsp.url") or ""),
            str(row.get("rtsp.content-base") or ""),
            str(row.get("xml.tag") or ""),
            str(row.get("xml.attribute") or ""),
        ]
        keyword_evidence = keyword_hits(combined_values)
        if keyword_evidence:
            score += 10 + min(12, len(keyword_evidence) * 2)
            evidence.extend(keyword_evidence[:6])

        if str(row.get("udp.port") or "").strip() == "3702":
            score += 12
            evidence.append("WS-Discovery/ONVIF UDP 3702")
        if str(row.get("udp.port") or "").strip() == "1900":
            score += 8
            evidence.append("SSDP UDP 1900")
        if str(row.get("rtsp.url") or "").strip():
            score += 20
            evidence.append("RTSP URL observed")
        if str(row.get("rtsp.content-base") or "").strip():
            score += 10
            evidence.append("RTSP content-base observed")
        if "onvif" in str(row.get("http.request.uri") or "").lower() or "device_service" in str(row.get("http.request.uri") or "").lower():
            score += 18
            evidence.append("ONVIF device_service URI")
        if "onvif" in str(row.get("xml.attribute") or "").lower() or "networkvideotransmitter" in str(row.get("xml.attribute") or "").lower():
            score += 16
            evidence.append("ONVIF XML attribute")
        if any(token in str(row.get("xml.tag") or "").lower() for token in ("probe", "probematches", "xaddr", "scopes", "types")):
            score += 10
            evidence.append("WS-Discovery XML tag")
        if str(row.get("http.www_authenticate") or "").strip():
            score += 4
            evidence.append("HTTP auth challenge")
        return score, evidence

    def _derive_findings(self, summary: Dict[str, Any]) -> List[str]:
        findings: List[str] = []
        counts = summary.get("protocol_counts", {})
        if summary.get("decryption_attempted") and summary.get("likely_decryption_success"):
            findings.append("Decryption likely succeeded: higher-layer traffic was decoded after authorized key material was supplied.")
        if summary.get("likely_missing_wifi_handshake"):
            findings.append("Wi-Fi decryption likely failed because the capture shows EAPOL traffic but no complete 4-way handshake for any observed pair.")
        if summary.get("http_authorization_frames"):
            findings.append("HTTP authorization headers were observed in decoded traffic; review for credential exposure.")
        if summary.get("rtsp_urls"):
            findings.append("RTSP requests were decoded; saved URLs and transport headers can be used to pivot into camera or NVR identification.")
        if summary.get("ws_discovery_frames"):
            findings.append("WS-Discovery-like traffic was observed; review XML tags, UDP 3702 activity, and ranked device leads for ONVIF pivots.")
        if summary.get("ssdp_frames"):
            findings.append("SSDP-like discovery traffic was observed; UPnP/HTTP metadata may identify camera or NVR services.")
        if summary.get("camera_indicators"):
            findings.append("Camera-like strings were observed across passive artifacts (HTTP, TLS, DNS, RTSP, or certificate names).")
        if summary.get("device_leads"):
            findings.append("Ranked device leads were generated from passive protocol evidence for likely camera-related endpoints.")
        if counts.get("http_frames", 0) == 0 and counts.get("tls_frames", 0) > 0 and not summary.get("tls_sni"):
            findings.append("TLS traffic was present without retained SNI values, which may indicate encrypted application traffic without hostname visibility.")
        if counts.get("ip_frames", 0) == 0 and counts.get("data_frames", 0) > 0 and not summary.get("decryption_attempted"):
            findings.append("802.11 data frames were present but no decryption material was provided, so higher-layer extraction will remain limited.")
        if not findings:
            findings.append("No strong indicators were extracted from this capture.")
        return findings

    def _collect_images(self, directory: Path, *, source: str, object_type: str) -> List[str]:
        saved: List[str] = []
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in IMAGE_EXTENSIONS and not self._looks_like_image(path):
                continue
            target = self._copy_image(path, source=source, object_type=object_type)
            if target:
                saved.append(target)
        return saved

    def _looks_like_image(self, path: Path) -> bool:
        if not self.tools["file"]:
            return False
        result = run_command([self.tools["file"], "--brief", "--mime-type", str(path)], timeout=15)
        return str(result.get("stdout") or "").strip().startswith("image/")

    def _copy_image(self, path: Path, *, source: str, object_type: str) -> str:
        self.image_dir.mkdir(parents=True, exist_ok=True)
        target = self.image_dir / f"{now_ts()}_{safe_label(path.name)}"
        suffix = 1
        while target.exists():
            target = self.image_dir / f"{now_ts()}_{suffix}_{safe_label(path.name)}"
            suffix += 1
        try:
            shutil.copy2(path, target)
            sidecar = target.with_suffix(target.suffix + ".json")
            sidecar.write_text(
                json.dumps(
                    {
                        "source": source,
                        "object_type": object_type,
                        "original_path": str(path),
                    },
                    indent=2,
                    ensure_ascii=True,
                ),
                encoding="utf-8",
            )
            self.saved_images.append(str(target))
            return str(target)
        except OSError:
            return ""

    def _render_summary(self, report: Dict[str, Any]) -> str:
        lines = [
            "GhostRecon Decrypt Test Summary",
            f"Generated: {report.get('generated_at', 0)}",
            f"Run dir: {report.get('run_dir', '')}",
            f"PCAPs analyzed: {len(report.get('pcaps', []))}",
            f"Saved images: {len(report.get('saved_images', []))}",
            "",
            "Authorized input summary:",
            json.dumps(report.get("authorized_inputs", {}), indent=2, ensure_ascii=True),
            "",
        ]
        for item in report.get("pcaps", []):
            lines.append(self._render_pcap_summary(item))
            lines.append("")
        return "\n".join(lines).strip() + "\n"

    def _render_pcap_summary(self, pcap_report: Dict[str, Any]) -> str:
        summary = pcap_report.get("summary", {})
        lines = [
            f"PCAP: {pcap_report.get('pcap', '')}",
            "Findings:",
        ]
        for finding in pcap_report.get("findings", []):
            lines.append(f"- {finding}")
        lines.extend(
            [
                "Counts:",
                json.dumps(summary.get("protocol_counts", {}), indent=2, ensure_ascii=True),
                "Key indicators:",
                json.dumps(
                    {
                        "http_hosts": summary.get("http_hosts", []),
                        "tls_sni": summary.get("tls_sni", []),
                        "dns_names": summary.get("dns_names", []),
                        "dhcp_hostnames": summary.get("dhcp_hostnames", []),
                        "rtsp_urls": summary.get("rtsp_urls", []),
                        "ws_discovery_frames": summary.get("ws_discovery_frames", 0),
                        "ssdp_frames": summary.get("ssdp_frames", 0),
                        "camera_indicators": summary.get("camera_indicators", []),
                        "top_endpoints": summary.get("top_endpoints", []),
                        "device_leads": summary.get("device_leads", [])[:5],
                    },
                    indent=2,
                    ensure_ascii=True,
                ),
            ]
        )
        return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized Wi-Fi/TLS decryption test harness for GhostRedRecon")
    parser.add_argument("--pcap", action="append", default=[], help="Specific pcap or pcapng to analyze")
    parser.add_argument("--pcap-limit", type=int, default=3, help="Recent capture count when --pcap is omitted")
    parser.add_argument("--wifi-key", action="append", default=[], help="Authorized Wi-Fi key in SSID:passphrase form")
    parser.add_argument("--wifi-psk", action="append", default=[], help="Authorized Wi-Fi PSK in SSID:hexpsk form")
    parser.add_argument("--tls-keylog", default="", help="Authorized TLS key log file path")
    parser.add_argument("--timeout", type=int, default=300, help="Per-tshark timeout in seconds")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return GhostReconDecryptTest(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
