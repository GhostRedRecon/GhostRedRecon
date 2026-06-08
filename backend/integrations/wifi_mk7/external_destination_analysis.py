from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

from backend.config.project_config import get_project_config

try:
    import geoip2.database as geoip2_database
except Exception:  # pragma: no cover - optional dependency
    geoip2_database = None

try:
    import maxminddb
except Exception:  # pragma: no cover - optional dependency
    maxminddb = None


class ExternalDestinationAnalysisEngine:
    VERSION = "2026-04-26-v1"
    LIMITATIONS = [
        "GeoIP accuracy depends on database freshness.",
        "ASN ownership may change.",
        "CDN infrastructure may mask backend.",
        "Routing does not prove ownership.",
        "Encrypted traffic limits visibility.",
    ]

    def __init__(self, root_dir: Path, tshark_path: str | None = None) -> None:
        self.root_dir = Path(root_dir)
        self.tshark_path = str(tshark_path or "").strip()

    @staticmethod
    def _now() -> int:
        return int(time.time())

    @staticmethod
    def _read_json(path_value: str) -> Dict[str, Any]:
        path = Path(str(path_value or "").strip())
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _normalize_ip(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            candidate = ipaddress.ip_address(text)
        except ValueError:
            return ""
        if candidate.version != 4:
            return ""
        return text

    @classmethod
    def _is_public_ip(cls, value: Any) -> bool:
        text = cls._normalize_ip(value)
        if not text:
            return False
        try:
            candidate = ipaddress.ip_address(text)
        except ValueError:
            return False
        return not (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_multicast
            or candidate.is_reserved
            or candidate.is_unspecified
        )

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score > 70:
            return "HIGH"
        if score > 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _country_display(country_code: str, country_name: str) -> str:
        code = str(country_code or "").strip().upper()
        name = str(country_name or "").strip()
        if code and name and name.upper() != code:
            return f"{code} {name}"
        return code or name or "UNKNOWN"

    @staticmethod
    def _split_multi_value(value: str) -> List[str]:
        items: List[str] = []
        for raw in str(value or "").replace(";", ",").split(","):
            cleaned = str(raw).strip()
            if cleaned and cleaned not in items:
                items.append(cleaned)
        return items

    def _feature_config(self) -> Dict[str, Any]:
        config = get_project_config()
        gui_features = ((config.get("gui") or {}).get("wifiMk7Features") or {})
        raw = (
            (config.get("wifiMk7") or {}).get("externalDestinationAnalysis")
            or gui_features.get("externalDestinationAnalysis")
            or {}
        )
        warning = str(
            raw.get("warning")
            or "Offline external destination analysis uses only retained PCAP evidence and local databases."
        )
        limitations = raw.get("limitations") or self.LIMITATIONS
        if not isinstance(limitations, list) or not limitations:
            limitations = list(self.LIMITATIONS)
        return {
            "enabled": bool(raw.get("enabled", True)),
            "warning": warning,
            "country_db_path": str(raw.get("countryDbPath") or "").strip(),
            "asn_db_path": str(raw.get("asnDbPath") or "").strip(),
            "limitations": [str(item).strip() for item in limitations if str(item).strip()],
        }

    def _candidate_db_paths(self, filename: str, configured: str) -> List[Path]:
        paths: List[Path] = []
        if configured:
            paths.append(Path(configured).expanduser())
        paths.extend(
            [
                self.root_dir / "data" / filename,
                self.root_dir / "data" / "geoip" / filename,
                self.root_dir / "config" / filename,
                self.root_dir / "evidence" / "geoip" / filename,
                Path("/usr/share/GeoIP") / filename,
                Path("/usr/local/share/GeoIP") / filename,
            ]
        )
        unique: List[Path] = []
        seen = set()
        for path in paths:
            try:
                resolved = path.expanduser().resolve()
            except Exception:
                resolved = path.expanduser()
            marker = str(resolved)
            if marker in seen:
                continue
            seen.add(marker)
            unique.append(resolved)
        return unique

    def _resolve_db_path(self, filename: str, configured: str) -> str:
        for path in self._candidate_db_paths(filename, configured):
            if path.exists() and path.is_file():
                return str(path)
        return ""

    def feature_status(self) -> Dict[str, Any]:
        config = self._feature_config()
        country_db_path = self._resolve_db_path("GeoLite2-Country.mmdb", config["country_db_path"])
        asn_db_path = self._resolve_db_path("GeoLite2-ASN.mmdb", config["asn_db_path"])
        return {
            "enabled": bool(config["enabled"]),
            "warning": config["warning"],
            "offline_only": True,
            "country_db_path": country_db_path,
            "asn_db_path": asn_db_path,
            "country_db_found": bool(country_db_path),
            "asn_db_found": bool(asn_db_path),
            "mmdb_reader_available": bool(geoip2_database or maxminddb),
            "limitations": list(config["limitations"] or self.LIMITATIONS),
        }

    def _lookup_country(self, ip_value: str, db_path: str) -> Dict[str, str]:
        if not db_path:
            return {"country": "UNKNOWN", "country_name": "", "source": ""}
        if geoip2_database is not None:
            try:
                with geoip2_database.Reader(db_path) as reader:
                    record = reader.country(ip_value)
                    return {
                        "country": str(record.country.iso_code or "UNKNOWN").upper(),
                        "country_name": str(record.country.name or "").strip(),
                        "source": db_path,
                    }
            except Exception:
                return {"country": "UNKNOWN", "country_name": "", "source": db_path}
        if maxminddb is not None:
            try:
                with maxminddb.open_database(db_path) as reader:
                    record = reader.get(ip_value) or {}
                country = (record.get("country") or {})
                names = country.get("names") or {}
                return {
                    "country": str(country.get("iso_code") or "UNKNOWN").upper(),
                    "country_name": str(names.get("en") or "").strip(),
                    "source": db_path,
                }
            except Exception:
                return {"country": "UNKNOWN", "country_name": "", "source": db_path}
        return {"country": "UNKNOWN", "country_name": "", "source": db_path}

    def _lookup_asn(self, ip_value: str, db_path: str) -> Dict[str, str]:
        if not db_path:
            return {"asn": "", "org": "", "source": ""}
        if geoip2_database is not None:
            try:
                with geoip2_database.Reader(db_path) as reader:
                    record = reader.asn(ip_value)
                    asn_number = int(record.autonomous_system_number or 0)
                    return {
                        "asn": f"AS{asn_number}" if asn_number > 0 else "",
                        "org": str(record.autonomous_system_organization or "").strip(),
                        "source": db_path,
                    }
            except Exception:
                return {"asn": "", "org": "", "source": db_path}
        if maxminddb is not None:
            try:
                with maxminddb.open_database(db_path) as reader:
                    record = reader.get(ip_value) or {}
                asn_number = int(record.get("autonomous_system_number") or 0)
                return {
                    "asn": f"AS{asn_number}" if asn_number > 0 else "",
                    "org": str(record.get("autonomous_system_organization") or "").strip(),
                    "source": db_path,
                }
            except Exception:
                return {"asn": "", "org": "", "source": db_path}
        return {"asn": "", "org": "", "source": db_path}

    @staticmethod
    def _behavior_label(endpoint: Dict[str, Any]) -> Dict[str, Any]:
        total_bytes = int(endpoint.get("total_bytes") or 0)
        packet_count = int(endpoint.get("packet_count") or 0)
        duration = float(endpoint.get("duration_seconds") or 0.0)
        packet_rate = float(endpoint.get("packet_rate_pps") or 0.0)
        protocols = {str(item).upper() for item in (endpoint.get("protocols") or []) if str(item).strip()}
        domains = {str(item).lower() for item in (endpoint.get("domains") or []) if str(item).strip()}
        reasons: List[str] = []
        label = "external_session"
        if total_bytes >= 524288 and duration >= 12.0 and packet_rate >= 1.5:
            label = "streaming"
            reasons.append("Sustained external flow volume observed.")
        elif total_bytes >= 196608 and packet_count >= 8 and duration <= 15.0:
            label = "burst_upload"
            reasons.append("Short higher-volume burst observed.")
        elif duration >= 30.0 and packet_count <= 12 and total_bytes <= 32768:
            label = "heartbeat"
            reasons.append("Low-volume keepalive pattern observed.")
        elif packet_count >= 6 and duration >= 20.0:
            label = "telemetry"
            reasons.append("Repeated external packet pattern observed.")
        elif any(token in domain for domain in domains for token in ("telemetry", "metrics", "mqtt", "api", "iot", "device")) and packet_count >= 3:
            label = "telemetry"
            reasons.append("Domain naming and packet repetition align with telemetry traffic.")
        elif "TLS" in protocols or "QUIC" in protocols:
            label = "encrypted_session"
            reasons.append("Encrypted external session observed.")
        elif "HTTP" in protocols:
            label = "http_session"
            reasons.append("HTTP host evidence observed.")
        else:
            reasons.append("External session observed without stronger behavior markers.")
        return {"behavior": label, "reasons": reasons}

    @classmethod
    def _confidence_score(cls, endpoint: Dict[str, Any]) -> int:
        score = 10
        if str(endpoint.get("country") or "").upper() not in {"", "UNKNOWN"}:
            score += 20
        if str(endpoint.get("asn") or "").strip():
            score += 20
        if str(endpoint.get("org") or "").strip():
            score += 20
        if list(endpoint.get("domains") or []) or list(endpoint.get("tls_server_names") or []) or list(endpoint.get("http_hosts") or []):
            score += 30
        if str(endpoint.get("behavior") or "") in {"telemetry", "streaming", "burst_upload", "heartbeat"}:
            score += 10
        return max(0, min(100, score))

    def _extract_from_pcap(self, pcap_path: str, target_ip: str) -> Dict[str, Any]:
        if not self.tshark_path:
            return {"ok": False, "error": "tshark unavailable", "external_endpoints": [], "external_ips": [], "dns_records": [], "tls_metadata": []}
        if not pcap_path or not Path(pcap_path).exists():
            return {"ok": False, "error": "target_filtered.pcapng missing", "external_endpoints": [], "external_ips": [], "dns_records": [], "tls_metadata": []}
        fields = [
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "frame.len",
            "frame.protocols",
            "dns.qry.name",
            "dns.a",
            "dns.aaaa",
            "tls.handshake.extensions_server_name",
            "http.host",
        ]
        command = [self.tshark_path, "-r", pcap_path, "-Y", "ip", "-T", "fields", "-E", "separator=\t", "-E", "quote=n"]
        for field_name in fields:
            command.extend(["-e", field_name])
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        except Exception as exc:
            return {
                "ok": False,
                "error": str(exc),
                "external_endpoints": [],
                "external_ips": [],
                "dns_records": [],
                "tls_metadata": [],
            }
        if result.returncode != 0:
            return {
                "ok": False,
                "error": (result.stderr or result.stdout or "tshark parse failed").strip(),
                "external_endpoints": [],
                "external_ips": [],
                "dns_records": [],
                "tls_metadata": [],
            }

        dns_map: Dict[str, List[str]] = {}
        endpoint_index: Dict[str, Dict[str, Any]] = {}
        external_ips: List[str] = []
        packets_observed = 0
        for raw in (result.stdout or "").splitlines():
            if not raw.strip():
                continue
            parts = raw.split("\t")
            while len(parts) < len(fields):
                parts.append("")
            (
                ts_text,
                ip_src,
                ip_dst,
                tcp_src,
                tcp_dst,
                udp_src,
                udp_dst,
                frame_len,
                frame_protocols,
                dns_name,
                dns_a,
                dns_aaaa,
                tls_sni,
                http_host,
            ) = parts[: len(fields)]
            ip_src = self._normalize_ip(ip_src)
            ip_dst = self._normalize_ip(ip_dst)
            if not ip_src or not ip_dst:
                continue
            if dns_name:
                for resolved_ip in [*self._split_multi_value(dns_a), *self._split_multi_value(dns_aaaa)]:
                    if not self._is_public_ip(resolved_ip):
                        continue
                    bucket = dns_map.setdefault(resolved_ip, [])
                    for domain in self._split_multi_value(dns_name):
                        if domain not in bucket:
                            bucket.append(domain)
            if ip_src != target_ip and ip_dst != target_ip:
                continue
            remote_ip = ip_dst if ip_src == target_ip else ip_src
            if not self._is_public_ip(remote_ip):
                continue
            packets_observed += 1
            if remote_ip not in external_ips:
                external_ips.append(remote_ip)
            try:
                ts_value = float(ts_text or 0.0)
            except ValueError:
                ts_value = 0.0
            length_value = int(float(frame_len or 0))
            src_port = str(tcp_src or udp_src or "").strip()
            dst_port = str(tcp_dst or udp_dst or "").strip()
            transport = "TCP" if (tcp_src or tcp_dst) else ("UDP" if (udp_src or udp_dst) else "IP")
            protocols_text = str(frame_protocols or "").lower()
            if http_host:
                protocol = "HTTP"
            elif "quic" in protocols_text:
                protocol = "QUIC"
            elif str(dst_port) == "443" or str(src_port) == "443" or str(tls_sni or "").strip() or "tls" in protocols_text:
                protocol = "TLS"
            elif "dns" in protocols_text:
                protocol = "DNS"
            else:
                protocol = transport
            endpoint = endpoint_index.setdefault(
                remote_ip,
                {
                    "ip": remote_ip,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "first_seen": ts_value or 0.0,
                    "last_seen": ts_value or 0.0,
                    "protocols": [],
                    "ports": [],
                    "domains": [],
                    "dns_queries": [],
                    "tls_server_names": [],
                    "http_hosts": [],
                    "outbound_packets": 0,
                    "inbound_packets": 0,
                },
            )
            endpoint["packet_count"] = int(endpoint.get("packet_count") or 0) + 1
            endpoint["total_bytes"] = int(endpoint.get("total_bytes") or 0) + max(0, length_value)
            endpoint["first_seen"] = min(float(endpoint.get("first_seen") or ts_value or 0.0), ts_value or float(endpoint.get("first_seen") or 0.0))
            endpoint["last_seen"] = max(float(endpoint.get("last_seen") or ts_value or 0.0), ts_value or float(endpoint.get("last_seen") or 0.0))
            if protocol not in endpoint["protocols"]:
                endpoint["protocols"].append(protocol)
            observed_port = int(dst_port or src_port or 0)
            if observed_port > 0 and observed_port not in endpoint["ports"]:
                endpoint["ports"].append(observed_port)
            if ip_src == target_ip:
                endpoint["outbound_packets"] = int(endpoint.get("outbound_packets") or 0) + 1
            else:
                endpoint["inbound_packets"] = int(endpoint.get("inbound_packets") or 0) + 1
            for domain in dns_map.get(remote_ip, []):
                if domain not in endpoint["dns_queries"]:
                    endpoint["dns_queries"].append(domain)
            for domain in self._split_multi_value(tls_sni):
                if domain and domain not in endpoint["tls_server_names"]:
                    endpoint["tls_server_names"].append(domain)
            for domain in self._split_multi_value(http_host):
                if domain and domain not in endpoint["http_hosts"]:
                    endpoint["http_hosts"].append(domain)

        rendered_endpoints: List[Dict[str, Any]] = []
        dns_records: List[Dict[str, Any]] = []
        tls_records: List[Dict[str, Any]] = []
        for ip_value in sorted(endpoint_index.keys()):
            endpoint = endpoint_index[ip_value]
            duration = max(0.0, float(endpoint["last_seen"]) - float(endpoint["first_seen"]))
            packet_rate = (int(endpoint["packet_count"]) / duration) if duration > 0 else float(endpoint["packet_count"])
            domains = []
            for bucket in (endpoint["tls_server_names"], endpoint["http_hosts"], endpoint["dns_queries"]):
                for domain in bucket:
                    if domain not in domains:
                        domains.append(domain)
            rendered_endpoints.append(
                {
                    **endpoint,
                    "domains": domains,
                    "duration_seconds": round(duration, 2),
                    "packet_rate_pps": round(packet_rate, 2),
                }
            )
            if endpoint["dns_queries"] or endpoint["http_hosts"]:
                dns_records.append(
                    {
                        "ip": ip_value,
                        "dns_queries": list(endpoint["dns_queries"]),
                        "http_hosts": list(endpoint["http_hosts"]),
                    }
                )
            if endpoint["tls_server_names"]:
                tls_records.append(
                    {
                        "ip": ip_value,
                        "server_names": list(endpoint["tls_server_names"]),
                    }
                )
        rendered_endpoints.sort(
            key=lambda item: (
                int(item.get("total_bytes") or 0),
                int(item.get("packet_count") or 0),
                float(item.get("duration_seconds") or 0.0),
            ),
            reverse=True,
        )
        return {
            "ok": True,
            "error": "",
            "external_endpoints": rendered_endpoints,
            "external_ips": sorted(external_ips),
            "dns_records": dns_records,
            "tls_metadata": tls_records,
            "packets_observed": packets_observed,
        }

    def analyze(
        self,
        *,
        target_id: str,
        target_filtered_pcap: str,
        ddi_resolution_path: str,
        service_audit_trace_path: str,
    ) -> Dict[str, Any]:
        feature = self.feature_status()
        ddi_resolution = self._read_json(ddi_resolution_path)
        service_audit = self._read_json(service_audit_trace_path)
        validated_candidates = list(ddi_resolution.get("validated_candidates") or [])
        target_ip = str(((service_audit.get("target_validation") or {}).get("target_ip") or "")).strip()
        if not target_ip and validated_candidates:
            target_ip = str(validated_candidates[0].get("candidate_ip") or "").strip()
        if not target_ip:
            return {
                "target_id": target_id,
                "target_ip": "",
                "analysis_state": "SKIPPED_NO_VALIDATED_IP",
                "offline_only": True,
                "summary": {
                    "china_asn_detected": False,
                    "external_telemetry_detected": False,
                    "external_endpoint_count": 0,
                },
                "assessment": "No validated target IP was retained, so external destination analysis did not run.",
                "confidence_score": 0,
                "confidence": "LOW",
                "limitations": list(feature["limitations"]),
                "data_sources": feature,
                "external_endpoints": [],
                "evidence_artifacts": {},
            }
        if not feature["enabled"]:
            return {
                "target_id": target_id,
                "target_ip": target_ip,
                "analysis_state": "DISABLED",
                "offline_only": True,
                "summary": {
                    "china_asn_detected": False,
                    "external_telemetry_detected": False,
                    "external_endpoint_count": 0,
                },
                "assessment": "External destination analysis is disabled by project configuration.",
                "confidence_score": 0,
                "confidence": "LOW",
                "limitations": list(feature["limitations"]),
                "data_sources": feature,
                "external_endpoints": [],
                "evidence_artifacts": {},
            }

        extraction = self._extract_from_pcap(target_filtered_pcap, target_ip)
        if not extraction.get("ok"):
            return {
                "target_id": target_id,
                "target_ip": target_ip,
                "analysis_state": "UNAVAILABLE",
                "offline_only": True,
                "summary": {
                    "china_asn_detected": False,
                    "external_telemetry_detected": False,
                    "external_endpoint_count": 0,
                },
                "assessment": f"External destination analysis could not parse the retained PCAP: {extraction.get('error') or 'unavailable input'}",
                "confidence_score": 0,
                "confidence": "LOW",
                "limitations": list(feature["limitations"]),
                "data_sources": feature,
                "external_endpoints": [],
                "external_ips": [],
                "dns_records": [],
                "tls_metadata": [],
                "evidence_artifacts": {},
            }

        enriched_endpoints: List[Dict[str, Any]] = []
        for endpoint in extraction["external_endpoints"]:
            country = self._lookup_country(endpoint["ip"], feature["country_db_path"])
            asn = self._lookup_asn(endpoint["ip"], feature["asn_db_path"])
            behavior = self._behavior_label(endpoint)
            rendered = {
                "ip": endpoint["ip"],
                "country": country["country"],
                "country_name": country["country_name"],
                "country_display": self._country_display(country["country"], country["country_name"]),
                "asn": asn["asn"],
                "org": asn["org"],
                "domain": next(iter(endpoint.get("domains") or []), ""),
                "domains": list(endpoint.get("domains") or []),
                "protocol": next(iter(endpoint.get("protocols") or []), "IP"),
                "protocols": list(endpoint.get("protocols") or []),
                "behavior": behavior["behavior"],
                "behavior_reasons": list(behavior["reasons"] or []),
                "observed_ports": sorted(int(item) for item in (endpoint.get("ports") or []) if int(item) > 0),
                "packet_count": int(endpoint.get("packet_count") or 0),
                "total_bytes": int(endpoint.get("total_bytes") or 0),
                "duration_seconds": round(float(endpoint.get("duration_seconds") or 0.0), 2),
                "packet_rate_pps": round(float(endpoint.get("packet_rate_pps") or 0.0), 2),
                "outbound_packets": int(endpoint.get("outbound_packets") or 0),
                "inbound_packets": int(endpoint.get("inbound_packets") or 0),
                "dns_queries": list(endpoint.get("dns_queries") or []),
                "tls_server_names": list(endpoint.get("tls_server_names") or []),
                "http_hosts": list(endpoint.get("http_hosts") or []),
                "geoip_evidence": {
                    "country_source": country["source"],
                    "asn_source": asn["source"],
                },
            }
            rendered["confidence_score"] = self._confidence_score(rendered)
            rendered["confidence"] = self._confidence_label(rendered["confidence_score"])
            rendered["evidence"] = {
                "country": rendered["country_display"],
                "asn": rendered["asn"],
                "org": rendered["org"],
                "domains": rendered["domains"],
                "dns_queries": rendered["dns_queries"],
                "tls_server_names": rendered["tls_server_names"],
                "http_hosts": rendered["http_hosts"],
                "observed_ports": rendered["observed_ports"],
                "packet_count": rendered["packet_count"],
                "total_bytes": rendered["total_bytes"],
                "duration_seconds": rendered["duration_seconds"],
                "packet_rate_pps": rendered["packet_rate_pps"],
            }
            enriched_endpoints.append(rendered)

        china_detected = any(item.get("country") == "CN" and item.get("asn") for item in enriched_endpoints)
        telemetry_detected = any(str(item.get("behavior") or "") in {"telemetry", "heartbeat"} for item in enriched_endpoints)
        assessment = "No external endpoints were retained for this target."
        if enriched_endpoints:
            strongest = enriched_endpoints[0]
            if strongest.get("country") not in {"", "UNKNOWN"}:
                assessment = f"Device communicates with {strongest['country_display']}-hosted infrastructure."
            else:
                assessment = "Device communicates with external infrastructure."
            if strongest.get("behavior") in {"telemetry", "heartbeat", "streaming", "burst_upload"}:
                assessment += f" {strongest['behavior'].replace('_', ' ').capitalize()} pattern observed."
            else:
                assessment += " External session observed."
            assessment += " No malicious behavior observed."
        confidence_score = max([int(item.get("confidence_score") or 0) for item in enriched_endpoints] or [0])
        analysis_state = "ANALYZED" if enriched_endpoints else "NO_EXTERNAL_ENDPOINTS"
        return {
            "version": self.VERSION,
            "analyzed_at": self._now(),
            "target_id": target_id,
            "target_ip": target_ip,
            "analysis_state": analysis_state,
            "offline_only": True,
            "summary": {
                "china_asn_detected": china_detected,
                "external_telemetry_detected": telemetry_detected,
                "external_endpoint_count": len(enriched_endpoints),
                "countries_observed": sorted({str(item.get("country") or "") for item in enriched_endpoints if str(item.get("country") or "").strip()}),
            },
            "assessment": assessment,
            "confidence_score": confidence_score,
            "confidence": self._confidence_label(confidence_score),
            "limitations": list(feature["limitations"]),
            "data_sources": {
                **feature,
                "target_filtered_pcap": str(target_filtered_pcap or ""),
                "ddi_resolution_path": str(ddi_resolution_path or ""),
                "service_audit_trace_path": str(service_audit_trace_path or ""),
            },
            "external_endpoints": enriched_endpoints,
            "external_ips": list(extraction.get("external_ips") or []),
            "dns_records": list(extraction.get("dns_records") or []),
            "tls_metadata": list(extraction.get("tls_metadata") or []),
            "evidence_artifacts": {},
        }
