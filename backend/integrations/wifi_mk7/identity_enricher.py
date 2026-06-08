from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


class WiFiIdentityEnricher:
    def __init__(self, root_dir: Path, tshark_path: str | None) -> None:
        self.root_dir = root_dir
        self.tshark_path = tshark_path
        self.zeek_path = shutil.which("zeek")
        self.config_path = root_dir / "config" / "wifi_mk7_blue_enrichment.json"
        self.last_error = ""

    def _run(self, cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {"enabled": False, "profiles": []}
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {
                    "enabled": bool(data.get("enabled")),
                    "profiles": list(data.get("profiles") or []),
                }
        except Exception:
            pass
        return {"enabled": False, "profiles": []}

    def status(self) -> Dict[str, Any]:
        config = self._load_config()
        return {
            "enabled": bool(config.get("enabled")),
            "configured_profiles": len(config.get("profiles") or []),
            "config_path": str(self.config_path),
            "available": bool(self.tshark_path),
            "zeek_available": bool(self.zeek_path),
            "last_error": self.last_error,
        }

    def configured(self) -> bool:
        config = self._load_config()
        return bool(self.tshark_path and config.get("enabled") and config.get("profiles"))

    def _decryption_options(self, profiles: List[Dict[str, Any]]) -> List[str]:
        options: List[str] = []
        if not profiles:
            return options
        options.extend(["-o", "wlan.enable_decryption:TRUE"])
        for profile in profiles:
            key_string = str(profile.get("tshark_key") or "").strip()
            if key_string:
                options.extend(["-o", f'uat:80211_keys:{key_string}'])
                continue
            ssid = str(profile.get("ssid") or "").strip()
            passphrase = str(profile.get("passphrase") or "").strip()
            if ssid and passphrase:
                options.extend(["-o", f'uat:80211_keys:"wpa-pwd","{passphrase}:{ssid}"'])
        return options

    def enrich_pcap(self, pcap_path: str, *, enable_zeek: bool = True) -> Dict[str, Any]:
        config = self._load_config()
        profiles = list(config.get("profiles") or [])
        if not self.tshark_path:
            return {"ok": False, "identities": [], "error": "tshark unavailable"}
        decryption_options = self._decryption_options(profiles) if (config.get("enabled") and profiles) else []

        command = [
            self.tshark_path,
            "-r",
            pcap_path,
            *decryption_options,
            "-T",
            "fields",
            "-E",
            "header=n",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=a",
            "-e",
            "frame.time_epoch",
            "-e",
            "wlan.sa",
            "-e",
            "wlan.da",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "dhcp.option.hostname",
            "-e",
            "dhcp.option.vendor_class_id",
            "-e",
            "dhcp.option.request_list_item",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.resp.name",
            "-e",
            "dns.ptr.domain_name",
            "-e",
            "http.host",
            "-e",
            "http.request.full_uri",
            "-e",
            "http.user_agent",
            "-e",
            "http.server",
            "-e",
            "rtsp.request",
            "-e",
            "rtsp.url",
            "-e",
            "tls.handshake.extensions_server_name",
            "-e",
            "tls.handshake.ja3",
            "-e",
            "tls.handshake.ja3s",
            "-e",
            "tls.handshake.ja4",
            "-e",
            "x509ce.dNSName",
            "-e",
            "http3.headers.authority",
            "-e",
            "http3.headers.server",
            "-e",
            "gquic.tag.sni",
        ]
        result = self._run(command, timeout=25)
        if result.returncode != 0:
            self.last_error = (result.stderr or result.stdout or "identity enrichment parse failed").strip()
            return {"ok": False, "identities": [], "error": self.last_error}

        identities: List[Dict[str, Any]] = []
        for line in (result.stdout or "").splitlines():
            parts = (line or "").split("\t")
            while len(parts) < 25:
                parts.append("")
            source_ip = str(parts[3] or "").strip()
            destination_ip = str(parts[4] or "").strip()
            hostname = str(parts[5] or "").strip()
            vendor_class_id = str(parts[6] or "").strip()
            request_list = str(parts[7] or "").strip()
            query_name = str(parts[8] or "").strip()
            response_name = str(parts[9] or "").strip()
            ptr_name = str(parts[10] or "").strip()
            http_host = str(parts[11] or "").strip()
            http_uri = str(parts[12] or "").strip()
            user_agent = str(parts[13] or "").strip()
            http_server = str(parts[14] or "").strip()
            rtsp_request = str(parts[15] or "").strip()
            rtsp_url = str(parts[16] or "").strip()
            server_name = str(parts[17] or "").strip()
            tls_ja3 = str(parts[18] or "").strip()
            tls_ja3s = str(parts[19] or "").strip()
            tls_ja4 = str(parts[20] or "").strip()
            subject_alt_name = str(parts[21] or "").strip()
            http3_authority = str(parts[22] or "").strip() if len(parts) > 22 else ""
            http3_server = str(parts[23] or "").strip() if len(parts) > 23 else ""
            gquic_sni = str(parts[24] or "").strip() if len(parts) > 24 else ""
            if not any(
                (
                    hostname,
                    vendor_class_id,
                    request_list,
                    query_name,
                    response_name,
                    ptr_name,
                    http_host,
                    http_uri,
                    user_agent,
                    http_server,
                    rtsp_request,
                    rtsp_url,
                    server_name,
                    tls_ja3,
                    tls_ja3s,
                    tls_ja4,
                    subject_alt_name,
                    http3_authority,
                    http3_server,
                    gquic_sni,
                    destination_ip,
                )
            ):
                continue
            query_names = self._split_multi(query_name)
            response_names = self._split_multi(response_name)
            ptr_names = self._split_multi(ptr_name)
            subject_alt_names = self._split_multi(subject_alt_name)
            destination_ips = self._split_multi(destination_ip)
            destination_domains = [
                *query_names,
                *response_names,
                *self._split_multi(http_host),
                *self._split_multi(server_name),
                *self._split_multi(http3_authority),
                *self._split_multi(gquic_sni),
            ]
            identities.append(
                {
                    "timestamp": float(parts[0] or 0.0),
                    "source": str(parts[1] or "").lower(),
                    "destination": str(parts[2] or "").lower(),
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "destination_ips": destination_ips,
                    "hostname": hostname,
                    "dhcp_vendor_class_id": vendor_class_id,
                    "dhcp_parameter_request_list": request_list,
                    "query_name": query_name,
                    "dns_response_name": response_name,
                    "ptr_name": ptr_name,
                    "query_names": query_names,
                    "response_names": response_names,
                    "ptr_names": ptr_names,
                    "http_host": http_host,
                    "http_uri": http_uri,
                    "http_user_agent": user_agent,
                    "http_server": http_server,
                    "rtsp_request": rtsp_request,
                    "rtsp_url": rtsp_url,
                    "tls_server_name": server_name,
                    "quic_server_name": gquic_sni or http3_authority,
                    "http3_authority": http3_authority,
                    "http3_server": http3_server,
                    "tls_ja3": tls_ja3,
                    "tls_ja3s": tls_ja3s,
                    "tls_ja4": tls_ja4,
                    "tls_subject_alt_names": subject_alt_names,
                    "resolved_domains": destination_domains[:10],
                    "mdns_service_type": self._infer_mdns_service_type(ptr_name),
                    "mdns_service_instance": self._infer_mdns_service_instance(ptr_name),
                    "protocol_source": "tshark",
                    "pcap_path": pcap_path,
                }
            )
        zeek_identities: List[Dict[str, Any]] = []
        service_inventory: List[Dict[str, Any]] = []
        protocol_summary: Dict[str, Any] = {
            "mdns_dns": 0,
            "http": 0,
            "tls": 0,
            "rtsp": 0,
            "quic": 0,
            "dhcp": 0,
            "tls_cert": 0,
            "vendor_wps": 0,
            "zeek": 0,
            "tshark": len(identities),
        }
        zeek_error = ""
        if self.zeek_path and enable_zeek:
            zeek_data = self._run_zeek_enrichment(pcap_path)
            zeek_identities = list(zeek_data.get("identities") or [])
            service_inventory = list(zeek_data.get("service_inventory") or [])
            zeek_error = str(zeek_data.get("error") or "")
            summary = zeek_data.get("protocol_summary") or {}
            for key in protocol_summary:
                if key in summary:
                    protocol_summary[key] = int(summary.get(key) or 0)
            protocol_summary["tshark"] = len(identities)
        merged = [*identities, *zeek_identities]
        protocol_summary.update(self._summarize_protocols(merged))
        destination_ip_counts, resolved_domain_counts = self._evidence_counters(merged)
        self.last_error = zeek_error
        return {
            "ok": True,
            "identities": merged,
            "service_inventory": service_inventory,
            "protocol_summary": protocol_summary,
            "destination_ip_counts": destination_ip_counts,
            "resolved_domain_counts": resolved_domain_counts,
            "error": "",
        }

    def _run_zeek_enrichment(self, pcap_path: str) -> Dict[str, Any]:
        if not self.zeek_path:
            return {"ok": False, "identities": [], "service_inventory": [], "protocol_summary": {}, "error": ""}
        with tempfile.TemporaryDirectory(prefix="ghostrecon_zeek_") as temp_dir:
            result = subprocess.run(
                [self.zeek_path, "-C", "-r", pcap_path, "local"],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "ok": False,
                    "identities": [],
                    "service_inventory": [],
                    "protocol_summary": {},
                    "error": (result.stderr or result.stdout or "zeek enrichment failed").strip(),
                }
            dns_rows = self._read_zeek_log(Path(temp_dir) / "dns.log")
            http_rows = self._read_zeek_log(Path(temp_dir) / "http.log")
            ssl_rows = self._read_zeek_log(Path(temp_dir) / "ssl.log")
            conn_rows = self._read_zeek_log(Path(temp_dir) / "conn.log")
            identities: List[Dict[str, Any]] = []
            service_inventory: List[Dict[str, Any]] = []
            protocol_summary = {
                "mdns_dns": 0,
                "http": 0,
                "tls": 0,
                "rtsp": 0,
                "quic": 0,
                "dhcp": 0,
                "tls_cert": 0,
                "vendor_wps": 0,
                "zeek": 0,
            }

            for row in dns_rows:
                query = str(row.get("query") or "").strip()
                if not query:
                    continue
                identities.append(
                    {
                        "timestamp": self._zeek_time(row.get("ts")),
                        "source": str(row.get("id.orig_h") or "").lower(),
                        "destination": str(row.get("id.resp_h") or "").lower(),
                        "query_name": query,
                        "ptr_name": query if ".local" in query.lower() or "_tcp" in query.lower() or "_udp" in query.lower() else "",
                        "mdns_service_type": self._infer_mdns_service_type(query),
                        "mdns_service_instance": self._infer_mdns_service_instance(query),
                        "protocol_source": "zeek:dns",
                        "pcap_path": pcap_path,
                    }
                )
                protocol_summary["mdns_dns"] += 1

            for row in http_rows:
                host = str(row.get("host") or "").strip()
                uri = str(row.get("uri") or "").strip()
                user_agent = str(row.get("user_agent") or "").strip()
                if not any((host, uri, user_agent)):
                    continue
                identities.append(
                    {
                        "timestamp": self._zeek_time(row.get("ts")),
                        "source": str(row.get("id.orig_h") or "").lower(),
                        "destination": str(row.get("id.resp_h") or "").lower(),
                        "http_host": host,
                        "http_uri": uri,
                        "http_user_agent": user_agent,
                        "destination_ip": str(row.get("id.resp_h") or "").lower(),
                        "protocol_source": "zeek:http",
                        "pcap_path": pcap_path,
                    }
                )
                protocol_summary["http"] += 1

            for row in ssl_rows:
                server_name = str(row.get("server_name") or "").strip()
                subject = str(row.get("subject") or "").strip()
                issuer = str(row.get("issuer") or "").strip()
                if not any((server_name, subject, issuer)):
                    continue
                identities.append(
                    {
                        "timestamp": self._zeek_time(row.get("ts")),
                        "source": str(row.get("id.orig_h") or "").lower(),
                        "destination": str(row.get("id.resp_h") or "").lower(),
                        "tls_server_name": server_name,
                        "tls_certificate_subject": subject,
                        "tls_certificate_issuer": issuer,
                        "protocol_source": "zeek:ssl",
                        "pcap_path": pcap_path,
                    }
                )
                protocol_summary["tls"] += 1
                if subject or issuer:
                    protocol_summary["tls_cert"] += 1

            for row in conn_rows:
                service_name = str(row.get("service") or "").strip().lower()
                if not service_name or service_name == "-":
                    continue
                destination = str(row.get("id.resp_h") or "").lower()
                source = str(row.get("id.orig_h") or "").lower()
                transport = str(row.get("proto") or "").lower()
                port = self._safe_int(row.get("id.resp_p"))
                detail = str(row.get("conn_state") or "").strip()
                service_inventory.append(
                    {
                        "timestamp": self._zeek_time(row.get("ts")),
                        "source": source,
                        "destination": destination,
                        "service_name": service_name,
                        "service_port": port,
                        "transport": transport,
                        "protocol_source": "zeek:conn",
                        "evidence_detail": detail,
                        "direction": "outbound",
                        "pcap_path": pcap_path,
                    }
                )
                if "rtsp" in service_name or port == 554:
                    protocol_summary["rtsp"] += 1
                protocol_summary["zeek"] += 1

            return {
                "ok": True,
                "identities": identities,
                "service_inventory": service_inventory,
                "protocol_summary": protocol_summary,
                "error": "",
            }

    @staticmethod
    def _read_zeek_log(path: Path) -> List[Dict[str, str]]:
        if not path.exists():
            return []
        fields: List[str] = []
        rows: List[Dict[str, str]] = []
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = str(raw_line or "")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#") or not fields:
                continue
            parts = line.split("\t")
            padded = parts + [""] * max(0, len(fields) - len(parts))
            rows.append({field: padded[index] for index, field in enumerate(fields)})
        return rows

    @staticmethod
    def _zeek_time(value: Any) -> float:
        try:
            return float(value or 0.0)
        except Exception:
            return 0.0

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            return int(str(value or "0"))
        except Exception:
            return 0

    @staticmethod
    def _infer_mdns_service_type(value: str) -> str:
        text = str(value or "").strip().lower()
        if "_rtsp._tcp" in text:
            return "_rtsp._tcp"
        if "_onvif._tcp" in text:
            return "_onvif._tcp"
        if "_http._tcp" in text:
            return "_http._tcp"
        if "_https._tcp" in text:
            return "_https._tcp"
        if "_hap._tcp" in text:
            return "_hap._tcp"
        if "_googlecast._tcp" in text:
            return "_googlecast._tcp"
        if "_ipps._tcp" in text:
            return "_ipps._tcp"
        return ""

    @staticmethod
    def _infer_mdns_service_instance(value: str) -> str:
        text = str(value or "").strip()
        lowered = text.lower()
        for marker in ("._tcp", "._udp"):
            if marker in lowered and "." in text:
                return text.split(".", 1)[0].strip()
        return ""

    @staticmethod
    def _split_multi(value: str) -> List[str]:
        text = str(value or "").strip()
        if not text:
            return []
        parts = [segment.strip() for segment in text.split(",")]
        return [segment for segment in parts if segment]

    def _summarize_protocols(self, identities: List[Dict[str, Any]]) -> Dict[str, int]:
        summary = {
            "mdns_dns": 0,
            "http": 0,
            "tls": 0,
            "rtsp": 0,
            "quic": 0,
            "dhcp": 0,
            "tls_cert": 0,
            "vendor_wps": 0,
        }
        for identity in identities:
            if any((identity.get("ptr_name"), identity.get("query_name"), identity.get("mdns_service_type"), identity.get("mdns_service_instance"))):
                summary["mdns_dns"] += 1
            if any((identity.get("http_host"), identity.get("http_uri"), identity.get("http_user_agent"), identity.get("http_server"), identity.get("http3_server"))):
                summary["http"] += 1
            if any((identity.get("tls_server_name"), identity.get("tls_ja3"), identity.get("tls_ja3s"), identity.get("tls_ja4"))):
                summary["tls"] += 1
            if any((identity.get("rtsp_request"), identity.get("rtsp_url"))):
                summary["rtsp"] += 1
            if any((identity.get("quic_server_name"), identity.get("http3_authority"))):
                summary["quic"] += 1
            if any((identity.get("hostname"), identity.get("dhcp_vendor_class_id"), identity.get("dhcp_parameter_request_list"))):
                summary["dhcp"] += 1
            if any((identity.get("tls_certificate_subject"), identity.get("tls_certificate_issuer"), identity.get("tls_subject_alt_names"))):
                summary["tls_cert"] += 1
        return summary

    def _evidence_counters(self, identities: List[Dict[str, Any]]) -> tuple[Dict[str, int], Dict[str, int]]:
        destination_ips: Counter[str] = Counter()
        resolved_domains: Counter[str] = Counter()
        for identity in identities:
            for ip in self._split_multi(str(identity.get("destination_ip") or "")) + list(identity.get("destination_ips") or []):
                if ip:
                    destination_ips[ip] += 1
            for domain in list(identity.get("resolved_domains") or []):
                lowered = str(domain or "").strip().lower()
                if lowered:
                    resolved_domains[lowered] += 1
        return dict(destination_ips), dict(resolved_domains)
