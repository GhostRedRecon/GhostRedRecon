from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import subprocess
import time
import uuid
from pathlib import Path
from shutil import which
from typing import Any, Dict, List

from backend.integrations.wifi_mk7.camera_signature_database import CAMERA_SIGNATURE_DATABASE


class ActiveFingerprintEngine:
    MAX_CANDIDATE_IPS = 8
    HTTP_PATHS = (
        "/",
        "/onvif/device_service",
        "/ISAPI/System/deviceInfo",
        "/ISAPI/Security/sessionLogin/capabilities",
        "/cgi-bin/api.cgi",
        "/cgi-bin/magicBox.cgi?action=getSystemInfo",
        "/axis-cgi/basicdeviceinfo.cgi",
        "/webapi/entry.cgi",
        "/web/admin.html",
        "/doc/page/login.asp",
    )
    RTSP_PORTS = (554, 8554, 10554)
    SNAPSHOT_PATHS = (
        "/ISAPI/Streaming/channels/101/picture",
        "/ISAPI/Streaming/channels/1/picture",
        "/cgi-bin/snapshot.cgi",
        "/cgi-bin/snapshot.cgi?channel=1",
        "/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=ghostredrecon",
        "/cgi-bin/api.cgi?cmd=Snap&channel=1&rs=ghostredrecon",
        "/cgi-bin/currentpic.cgi",
        "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1",
        "/cgi-bin/jpg/image.cgi",
        "/cgi-bin/viewer/video.jpg",
        "/cgi-bin/hi3510/snap.cgi",
        "/webcapture.jpg?command=snap&channel=1",
        "/webcapture.jpg?command=snap&channel=0",
        "/picture",
        "/picture/1/current",
        "/image.jpg",
        "/image/jpeg.cgi",
        "/mjpg/video.mjpg",
        "/video.mjpg",
        "/videostream.cgi",
        "/mjpeg",
        "/onvif/snapshot",
        "/snapshot.jpg",
        "/snap.jpg",
        "/camera/snapshot",
        "/img/snapshot.cgi",
    )
    RTSP_PATHS = (
        "/",
        "/Streaming/Channels/101",
        "/Streaming/Channels/1",
        "/cam/realmonitor?channel=1&subtype=0",
        "/cam/realmonitor?channel=1&subtype=1",
        "/h264Preview_01_main",
        "/h264Preview_01_sub",
        "/live/ch00_0",
        "/live/ch00_1",
        "/live.sdp",
        "/11",
        "/12",
        "/stream1",
        "/stream2",
        "/videoMain",
        "/videoSub",
        "/axis-media/media.amp",
    )

    def __init__(self, timeout_seconds: float = 3.0, root_dir: Path | None = None, preferred_interface: str = "wlan1") -> None:
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.root_dir = Path(root_dir) if root_dir else Path.cwd()
        self.preferred_interface = str(preferred_interface or "wlan1").strip() or "wlan1"
        self.image_dir = self.root_dir / "evidence" / "camera_images"
        self.protocol_dir = self.root_dir / "evidence" / "camera_protocol"
        self.ffmpeg_path = which("ffmpeg") or ""

    def probe_lead(self, lead: Dict[str, Any], *, route_interface: str = "", aggressive: bool = False) -> Dict[str, Any]:
        candidate_ips = self._candidate_ips(lead)
        if not candidate_ips:
            discovery = self._discover_onvif_candidates(route_interface=route_interface)
            discovered_ips = list(discovery.get("candidate_ips") or [])
            if discovered_ips:
                result = self.probe_ips(discovered_ips[: self.MAX_CANDIDATE_IPS], source="onvif_discovery_fallback", route_interface=route_interface)
                result["candidate_ip_reason"] = "fallback_onvif_discovery"
                result["discovery_fallback"] = discovery
                return result
            aggressive_discovery = self._discover_local_subnet_candidates(route_interface=route_interface) if aggressive else {}
            aggressive_ips = list(aggressive_discovery.get("candidate_ips") or [])
            if aggressive_ips:
                result = self.probe_ips(aggressive_ips[: self.MAX_CANDIDATE_IPS], source="aggressive_subnet_discovery", route_interface=route_interface)
                result["candidate_ip_reason"] = "fallback_aggressive_subnet_discovery"
                result["discovery_fallback"] = discovery
                result["aggressive_discovery"] = aggressive_discovery
                return result
            return {
                "ok": False,
                "error": "No candidate IPs available for active fingerprinting.",
                "candidate_ips": [],
                "candidate_ip_reason": self._candidate_ip_reason(lead),
                "discovery_fallback": discovery,
                "aggressive_discovery": aggressive_discovery if aggressive else {},
                "probes": [],
                "summary": {
                    "camera_positive": False,
                    "camera_positive_summary": "Probe failed: no candidate IP path could be inferred from current passive evidence.",
                    "http_hits": 0,
                    "onvif_hits": 0,
                    "rtsp_hits": 0,
                    "snapshot_hits": 0,
                    "matched_families": [],
                    "rtsp_frame_hits": 0,
                    "visual_artifact_count": 0,
                    "visual_artifacts": [],
                    "video_or_image_proof": False,
                    "proof_level": "NO_PROOF",
                },
            }
        return self.probe_ips(candidate_ips[: self.MAX_CANDIDATE_IPS], source="passive_evidence", route_interface=route_interface)

    def _discover_local_subnet_candidates(self, *, route_interface: str = "") -> Dict[str, Any]:
        active_interface = str(route_interface or self.preferred_interface or "").strip()
        if not active_interface:
            active_interface = self._default_route_interface()
        if not active_interface:
            return {"ok": False, "error": "No interface available for local subnet discovery.", "candidate_ips": []}
        subnet = self._interface_subnet(active_interface)
        if not subnet and active_interface != self.preferred_interface:
            subnet = self._interface_subnet(self.preferred_interface)
        if not subnet:
            fallback_interface = self._default_route_interface()
            if fallback_interface and fallback_interface != active_interface:
                active_interface = fallback_interface
                subnet = self._interface_subnet(active_interface)
        if not subnet:
            return {"ok": False, "error": "No local subnet route or address found.", "candidate_ips": [], "route_interface": active_interface}
        try:
            scan = subprocess.run(
                [
                    "nmap",
                    "-Pn",
                    "-p",
                    "80,443,554,8000,8080,8554,10554,3702",
                    "--open",
                    "-oG",
                    "-",
                    subnet,
                ],
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc), "candidate_ips": [], "route_interface": active_interface, "subnet": subnet}
        candidate_ips: List[str] = []
        hosts: List[Dict[str, Any]] = []
        for raw in (scan.stdout or "").splitlines():
            line = raw.strip()
            if not line.startswith("Host:"):
                continue
            match = re.search(r"Host:\s+([0-9.]+).*Ports:\s+(.*)$", line)
            if not match:
                continue
            ip_value = str(match.group(1) or "").strip()
            ports_blob = str(match.group(2) or "")
            if not self._is_routable_ip(ip_value):
                continue
            open_ports = []
            for part in ports_blob.split(","):
                port_fields = [segment.strip() for segment in part.split("/") if segment.strip()]
                if len(port_fields) >= 2 and port_fields[1] == "open":
                    open_ports.append(port_fields[0])
            if not open_ports:
                continue
            if ip_value not in candidate_ips:
                candidate_ips.append(ip_value)
            hosts.append({"ip": ip_value, "open_ports": open_ports[:8]})
        return {
            "ok": bool(candidate_ips),
            "route_interface": active_interface,
            "subnet": subnet,
            "candidate_ips": candidate_ips[: self.MAX_CANDIDATE_IPS],
            "hosts": hosts[: self.MAX_CANDIDATE_IPS],
        }

    def _discover_onvif_candidates(self, *, route_interface: str = "") -> Dict[str, Any]:
        multicast_ip = "239.255.255.250"
        port = 3702
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            "<e:Header>"
            f"<w:MessageID>urn:uuid:{uuid.uuid4()}</w:MessageID>"
            "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
            "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
            "</e:Header>"
            "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
        ).encode("utf-8")
        sock: socket.socket | None = None
        responses: List[Dict[str, Any]] = []
        candidate_ips: List[str] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(1.0)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(body, (multicast_ip, port))
            deadline = time.time() + min(3.0, self.timeout_seconds + 1.0)
            while time.time() < deadline:
                try:
                    payload, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                decoded = payload.decode("utf-8", errors="ignore")
                xaddrs = re.findall(r"https?://([0-9a-fA-F\.:]+)(?::\d+)?/", decoded)
                response_record = {
                    "from_ip": addr[0],
                    "matched_tokens": [token for token in ("onvif", "xaddrs", "networkvideotransmitter", "scopes") if token in decoded.lower()],
                    "xaddrs": xaddrs[:6],
                    "scopes": re.findall(r"<[^>]*Scopes[^>]*>(.*?)</[^>]*Scopes>", decoded, flags=re.IGNORECASE | re.DOTALL)[:2],
                    "response_excerpt": decoded[:512],
                }
                responses.append(response_record)
                for ip in [addr[0], *xaddrs]:
                    ip_text = str(ip).strip("[]")
                    if self._is_routable_ip(ip_text) and ip_text not in candidate_ips:
                        candidate_ips.append(ip_text)
        except Exception as exc:
            return {
                "ok": False,
                "error": str(exc),
                "route_interface": route_interface or "",
                "candidate_ips": [],
                "responses": [],
            }
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
        return {
            "ok": bool(candidate_ips),
            "route_interface": route_interface or "",
            "candidate_ips": candidate_ips[: self.MAX_CANDIDATE_IPS],
            "responses": responses[:8],
            "response_count": len(responses),
        }

    def probe_ip(self, ip: str, *, route_interface: str = "") -> Dict[str, Any]:
        if not self._is_routable_ip(ip):
            return {"ok": False, "error": "Invalid or unroutable IP address.", "candidate_ips": [], "probes": []}
        return self.probe_ips([ip], source="manual_ip", route_interface=route_interface)

    def probe_ips(self, candidate_ips: List[str], source: str = "manual_ip", route_interface: str = "") -> Dict[str, Any]:
        if candidate_ips:
            interface_check = self._validate_route_interface(candidate_ips[0], route_interface=route_interface)
            if not interface_check.get("ok"):
                return {
                    "ok": False,
                    "error": interface_check.get("error") or "Route interface validation failed.",
                    "route_interface": interface_check.get("route_interface") or "",
                    "required_interface": self.preferred_interface,
                    "candidate_ips": candidate_ips[:4],
                    "probes": [],
                }
        probes: List[Dict[str, Any]] = []
        for ip in candidate_ips[:4]:
            probes.append(
                {
                    "ip": ip,
                    "http": self._http_probe(ip),
                    "onvif": self._onvif_probe(ip),
                    "rtsp": self._rtsp_probe(ip),
                    "snapshot": self._snapshot_probe(ip),
                }
            )
        return {
            "ok": True,
            "source": source,
            "probe_started_at": int(time.time()),
            "route_interface": route_interface or self._route_interface(candidate_ips[0]),
            "candidate_ips": candidate_ips[:4],
            "probes": probes,
            "summary": self._summarize(probes),
        }

    def _candidate_ips(self, lead: Dict[str, Any]) -> List[str]:
        stable = dict(lead.get("stable_fingerprint") or {})
        evidence = list(lead.get("evidence_provenance") or [])
        services = list(((lead.get("service_exposure") or {}).get("service_inventory")) or [])
        cloud_endpoints = list(((lead.get("service_exposure") or {}).get("cloud_endpoints")) or [])
        neighbor_ips = self._neighbor_cache_candidates(lead)
        scored: Dict[str, float] = {}

        def bump(ip: str, score: float) -> None:
            if not self._is_routable_ip(ip):
                return
            try:
                private_bias = 40.0 if ipaddress.ip_address(ip).is_private else 0.0
            except ValueError:
                private_bias = 0.0
            scored[ip] = float(scored.get(ip) or 0.0) + float(score) + private_bias

        for bucket, weight in (
            (dict(stable.get("recurring_destination_ips") or {}), 12.0),
            (dict(stable.get("associated_network_recurring_ips") or {}), 11.0),
            (dict(lead.get("recurring_destination_profiles") or {}), 10.0),
            (dict(lead.get("destination_ip_counts") or {}), 8.0),
        ):
            for ip, count in bucket.items():
                bump(str(ip).strip(), min(40.0, float(count or 1) * weight))
        for entry in evidence:
            ip = str(entry.get("related_ip") or "").strip()
            if not ip:
                candidate_value = str(entry.get("value") or "").strip()
                if self._is_routable_ip(candidate_value):
                    ip = candidate_value
            if not ip:
                continue
            count = int(entry.get("count") or 1)
            protocol = str(entry.get("protocol") or "").lower()
            evidence_type = str(entry.get("type") or "").lower()
            weight = 4.0 * count
            if protocol in {"http", "rtsp", "tls", "quic", "mdns", "dns"}:
                weight += 8.0
            if evidence_type in {"http_host", "tls_sni", "rtsp_url", "mdns_ptr", "dhcp_hostname"}:
                weight += 6.0
            bump(ip, weight)

        for service in services:
            for field, weight in (("destination", 18.0), ("source", 10.0)):
                bump(str((service or {}).get(field) or "").strip(), weight)
            port = int((service or {}).get("service_port") or 0)
            if port in {80, 443, 554, 8080, 8000, 8554, 10554}:
                bump(str((service or {}).get("destination") or "").strip(), 12.0)

        associated_network = dict(lead.get("associated_network") or {})
        for service in list(((associated_network.get("service_exposure") or {}).get("service_inventory")) or []):
            for field, weight in (("destination", 16.0), ("source", 8.0)):
                bump(str((service or {}).get(field) or "").strip(), weight)
            port = int((service or {}).get("service_port") or 0)
            if port in {80, 443, 554, 8080, 8000, 8554, 10554, 3702}:
                bump(str((service or {}).get("destination") or "").strip(), 10.0)

        for endpoint in cloud_endpoints:
            endpoint_value = str(endpoint or "").strip()
            if self._is_routable_ip(endpoint_value):
                bump(endpoint_value, 6.0)

        for direct_value in (
            str(lead.get("ip") or "").strip(),
            str(lead.get("ip_address") or "").strip(),
            str(lead.get("local_ip") or "").strip(),
            str(lead.get("validated_ip") or "").strip(),
        ):
            if direct_value:
                bump(direct_value, 30.0)
        for bucket in (
            list(lead.get("ip_addresses") or []),
            list(lead.get("candidate_ip_addresses") or []),
        ):
            for ip_value in bucket:
                normalized = str(ip_value or "").strip()
                if normalized:
                    bump(normalized, 28.0)

        for ip in neighbor_ips:
            bump(ip, 32.0)

        return [
            ip for ip, _score in sorted(
                scored.items(),
                key=lambda item: (item[1], item[0]),
                reverse=True,
            )
        ]

    def _candidate_ip_reason(self, lead: Dict[str, Any]) -> str:
        stable = dict(lead.get("stable_fingerprint") or {})
        evidence = list(lead.get("evidence_provenance") or [])
        services = list(((lead.get("service_exposure") or {}).get("service_inventory")) or [])
        cloud_endpoints = list(((lead.get("service_exposure") or {}).get("cloud_endpoints")) or [])
        neighbor_ips = self._neighbor_cache_candidates(lead)
        reasons: List[str] = []
        if not dict(stable.get("recurring_destination_ips") or {}):
            reasons.append("no recurring destination IPs")
        if not dict(stable.get("associated_network_recurring_ips") or {}):
            reasons.append("no associated-network IPs")
        if not dict(lead.get("recurring_destination_profiles") or {}):
            reasons.append("no recurring destination profiles")
        if not dict(lead.get("destination_ip_counts") or {}):
            reasons.append("no destination IP counts")
        if not any(str(entry.get("related_ip") or "").strip() for entry in evidence):
            reasons.append("no related IPs in evidence provenance")
        if not services:
            reasons.append("no service inventory endpoints")
        associated_network = dict(lead.get("associated_network") or {})
        if not list(((associated_network.get("service_exposure") or {}).get("service_inventory")) or []):
            reasons.append("no associated-network services")
        if not cloud_endpoints:
            reasons.append("no cloud endpoint IPs")
        if not neighbor_ips:
            reasons.append("no local ARP/neighbor cache match")
        return ", ".join(reasons[:4]) or "no passive IP evidence retained"

    def _neighbor_cache_candidates(self, lead: Dict[str, Any]) -> List[str]:
        macs = {
            str(lead.get("bssid") or "").strip().lower(),
            str(lead.get("mac") or "").strip().lower(),
            str(lead.get("record_id") or "").strip().lower(),
        }
        macs = {mac for mac in macs if mac and ":" in mac}
        if not macs:
            return []
        candidates: List[str] = []
        arp_path = Path("/proc/net/arp")
        try:
            if arp_path.exists():
                for raw in arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                    parts = raw.split()
                    if len(parts) < 4:
                        continue
                    ip_value = parts[0].strip()
                    mac_value = parts[3].strip().lower()
                    if mac_value not in macs or not self._is_routable_ip(ip_value):
                        continue
                    if ip_value not in candidates:
                        candidates.append(ip_value)
        except Exception:
            pass
        if candidates:
            return candidates[: self.MAX_CANDIDATE_IPS]
        try:
            result = subprocess.run(
                ["/usr/sbin/ip", "neigh"],
                capture_output=True,
                text=True,
                timeout=max(1.0, self.timeout_seconds),
                check=False,
            )
        except Exception:
            return []
        if result.returncode != 0:
            return candidates[: self.MAX_CANDIDATE_IPS]
        for raw in (result.stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            ip_value = parts[0].strip()
            mac_value = ""
            if "lladdr" in parts:
                index = parts.index("lladdr")
                if index + 1 < len(parts):
                    mac_value = parts[index + 1].strip().lower()
            if mac_value not in macs or not self._is_routable_ip(ip_value):
                continue
            if ip_value not in candidates:
                candidates.append(ip_value)
        return candidates[: self.MAX_CANDIDATE_IPS]

    @staticmethod
    def _is_routable_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(str(value or "").strip())
            return not ip.is_multicast and not ip.is_unspecified
        except ValueError:
            return False

    def _http_probe(self, ip: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8000)):
            for path in self.HTTP_PATHS:
                result = self._single_http_probe(ip, port, path, use_tls=(scheme == "https"))
                if result.get("ok"):
                    findings.append(result)
                    if result.get("camera_hint"):
                        break
        matched_families = self._merge_family_matches(*(finding.get("matched_families") or [] for finding in findings))
        return {
            "ok": bool(findings),
            "camera_hint": any(bool(item.get("camera_hint")) for item in findings),
            "findings": findings[:8],
            "matched_families": matched_families[:6],
        }

    def _single_http_probe(self, ip: str, port: int, path: str, *, use_tls: bool) -> Dict[str, Any]:
        started = time.time()
        conn: Any = None
        try:
            if use_tls:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port=port, timeout=self.timeout_seconds, context=context)
            else:
                conn = http.client.HTTPConnection(ip, port=port, timeout=self.timeout_seconds)
            conn.request("GET", path, headers={"User-Agent": "GhostRedRecon/Probe", "Accept": "*/*"})
            response = conn.getresponse()
            body = response.read(768).decode("utf-8", errors="ignore")
            headers = {key.lower(): value for key, value in response.getheaders()}
            server = str(headers.get("server") or "")
            www_auth = str(headers.get("www-authenticate") or "")
            hint_blob = " ".join([server, www_auth, body]).lower()
            matched_families = self._match_families(
                "http",
                " ".join([server, www_auth, body, path]),
            )
            camera_hint = bool(matched_families) or any(
                token in hint_blob for token in ("onvif", "ip camera", "network camera", "hikvision", "dahua", "reolink", "rtsp", "uc-httpd", "goahead")
            )
            return {
                "ok": True,
                "scheme": "https" if use_tls else "http",
                "port": port,
                "path": path,
                "status": int(response.status),
                "reason": str(response.reason),
                "server": server,
                "www_authenticate": www_auth,
                "camera_hint": camera_hint,
                "matched_families": matched_families[:6],
                "latency_ms": round((time.time() - started) * 1000, 1),
            }
        except Exception as exc:
            return {"ok": False, "scheme": "https" if use_tls else "http", "port": port, "path": path, "error": str(exc)}
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    def _onvif_probe(self, ip: str) -> Dict[str, Any]:
        http_service = self._onvif_http_probe(ip)
        ws_discovery = self._onvif_ws_discovery_probe(ip)
        matched_families = self._merge_family_matches(
            http_service.get("matched_families") or [],
            ws_discovery.get("matched_families") or [],
        )
        return {
            "ok": bool(http_service.get("ok") or ws_discovery.get("ok")),
            "camera_hint": bool(http_service.get("camera_hint") or ws_discovery.get("camera_hint")),
            "http_service": http_service,
            "ws_discovery": ws_discovery,
            "matched_families": matched_families[:6],
        }

    def _onvif_http_probe(self, ip: str) -> Dict[str, Any]:
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            "<s:Header>"
            '<a:Action mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
            f"<a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>"
            "<a:To mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
            "</s:Header>"
            "<s:Body>"
            "<d:Probe>"
            "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
            "</d:Probe>"
            "</s:Body>"
            "</s:Envelope>"
        )
        started = time.time()
        conn: Any = None
        try:
            conn = http.client.HTTPConnection(ip, port=80, timeout=self.timeout_seconds)
            conn.request(
                "POST",
                "/onvif/device_service",
                body=body,
                headers={
                    "User-Agent": "GhostRedRecon/Probe",
                    "Content-Type": "application/soap+xml; charset=utf-8",
                    "Content-Length": str(len(body)),
                },
            )
            response = conn.getresponse()
            payload = response.read(2048).decode("utf-8", errors="ignore")
            lowered = payload.lower()
            onvif_hint = any(token in lowered for token in ("onvif", "networkvideotransmitter", "device_service", "tds:", "trt:"))
            matched_families = self._match_families("onvif", payload)
            return {
                "ok": True,
                "path": "/onvif/device_service",
                "status": int(response.status),
                "reason": str(response.reason),
                "camera_hint": onvif_hint or int(response.status) in {200, 400, 401},
                "matched_tokens": [token for token in ("onvif", "networkvideotransmitter", "device_service", "tds:", "trt:") if token in lowered],
                "matched_families": matched_families[:6],
                "latency_ms": round((time.time() - started) * 1000, 1),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    def _onvif_ws_discovery_probe(self, ip: str) -> Dict[str, Any]:
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            "<e:Header>"
            '<w:MessageID>urn:uuid:' + str(uuid.uuid4()) + "</w:MessageID>"
            '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
            '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
            "</e:Header>"
            "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
        ).encode("utf-8")
        sock: socket.socket | None = None
        started = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout_seconds)
            sock.sendto(body, (ip, 3702))
            payload, _ = sock.recvfrom(4096)
            decoded = payload.decode("utf-8", errors="ignore")
            lowered = decoded.lower()
            matched_families = self._match_families("onvif", decoded)
            xaddrs = re.findall(r"https?://([0-9a-fA-F\\.:]+)(?::\\d+)?/", decoded)
            scopes = re.findall(r"<[^>]*Scopes[^>]*>(.*?)</[^>]*Scopes>", decoded, flags=re.IGNORECASE | re.DOTALL)
            return {
                "ok": True,
                "status": "reply",
                "camera_hint": any(token in lowered for token in ("onvif", "networkvideotransmitter", "xaddrs", "scopes")) or bool(matched_families),
                "matched_tokens": [token for token in ("onvif", "networkvideotransmitter", "xaddrs", "scopes") if token in lowered],
                "xaddrs": [str(item).strip("[]") for item in xaddrs[:6]],
                "scopes": [str(item).strip() for item in scopes[:2]],
                "response_excerpt": decoded[:512],
                "matched_families": matched_families[:6],
                "latency_ms": round((time.time() - started) * 1000, 1),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    def _rtsp_probe(self, ip: str) -> Dict[str, Any]:
        started = time.time()
        attempts: List[Dict[str, Any]] = []
        for port in self.RTSP_PORTS:
            try:
                options_request = (
                    f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                    "CSeq: 1\r\n"
                    "User-Agent: GhostRedRecon/Probe\r\n\r\n"
                )
                options_response = self._rtsp_exchange(ip, port, options_request)
                data = str(options_response.get("response") or "")
                lowered = data.lower()
                public = self._header_value(data, "Public")
                server = self._header_value(data, "Server")
                describe_request = (
                    f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                    "CSeq: 2\r\n"
                    "Accept: application/sdp\r\n"
                    "User-Agent: GhostRedRecon/Probe\r\n\r\n"
                )
                describe_response = self._rtsp_exchange(ip, port, describe_request)
                describe_blob = str(describe_response.get("response") or "")
                matched_families = self._match_families("rtsp", " ".join([server, public, data, describe_blob]))
                camera_hint = bool(matched_families) or any(token in lowered for token in ("rtsp/1.0 200", "describe", "setup", "play", "digest", "basic"))
                transcript_path = self._save_protocol_artifact(
                    ip=ip,
                    port=port,
                    protocol="rtsp",
                    suffix="rtsp_probe",
                    payload=(
                        f"# OPTIONS\n{options_request}\n# OPTIONS_RESPONSE\n{data}\n\n"
                        f"# DESCRIBE\n{describe_request}\n# DESCRIBE_RESPONSE\n{describe_blob}"
                    ).encode("utf-8", errors="ignore"),
                    extension=".txt",
                )
                frame_capture = self._capture_rtsp_frame(
                    ip=ip,
                    port=port,
                    matched_families=matched_families,
                    root_describe_ok=str(describe_blob.splitlines()[0] if describe_blob else "").startswith("RTSP/1.0 200"),
                )
                attempts.append(
                    {
                        "ok": True,
                        "port": port,
                        "camera_hint": camera_hint,
                        "server": server,
                        "public": public,
                        "status_line": data.splitlines()[0] if data else "RTSP/1.0",
                        "describe_status_line": describe_blob.splitlines()[0] if describe_blob else "",
                        "supported_methods": [item.strip() for item in public.split(",") if item.strip()],
                        "response": data[:512],
                        "describe_response": describe_blob[:768],
                        "transcript_path": transcript_path,
                        "frame_capture_path": str(frame_capture.get("saved_path") or ""),
                        "frame_capture_url": str(frame_capture.get("url") or ""),
                        "frame_capture_error": str(frame_capture.get("error") or ""),
                        "ffmpeg_available": bool(self.ffmpeg_path),
                        "matched_families": matched_families[:6],
                        "latency_ms": round((time.time() - started) * 1000, 1),
                    }
                )
                if camera_hint:
                    break
            except Exception as exc:
                attempts.append({"ok": False, "port": port, "error": str(exc)})
        successful = [attempt for attempt in attempts if attempt.get("ok")]
        best = next((attempt for attempt in successful if attempt.get("camera_hint")), successful[0] if successful else attempts[0] if attempts else {"ok": False, "error": "No RTSP attempts executed"})
        result = dict(best)
        result["attempts"] = [dict(attempt) for attempt in attempts]
        result["matched_families"] = self._merge_family_matches(*(attempt.get("matched_families") or [] for attempt in successful))[:6]
        return result

    def _snapshot_probe(self, ip: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8000)):
            for path in self.SNAPSHOT_PATHS:
                result = self._single_snapshot_probe(ip, port, path, use_tls=(scheme == "https"))
                if result.get("ok"):
                    findings.append(result)
                    if result.get("image_hint"):
                        matched_families = self._merge_family_matches(*(finding.get("matched_families") or [] for finding in findings))
                        return {
                            "ok": True,
                            "image_hint": True,
                            "findings": findings[:6],
                            "matched_families": matched_families[:6],
                        }
        matched_families = self._merge_family_matches(*(finding.get("matched_families") or [] for finding in findings))
        return {
            "ok": bool(findings),
            "image_hint": any(bool(item.get("image_hint")) for item in findings),
            "findings": findings[:6],
            "matched_families": matched_families[:6],
        }

    def _single_snapshot_probe(self, ip: str, port: int, path: str, *, use_tls: bool) -> Dict[str, Any]:
        started = time.time()
        conn: Any = None
        try:
            if use_tls:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port=port, timeout=self.timeout_seconds, context=context)
            else:
                conn = http.client.HTTPConnection(ip, port=port, timeout=self.timeout_seconds)
            conn.request("GET", path, headers={"User-Agent": "GhostRedRecon/Probe", "Accept": "image/*,*/*"})
            response = conn.getresponse()
            payload = response.read(1024 * 1024)
            headers = {key.lower(): value for key, value in response.getheaders()}
            content_type = str(headers.get("content-type") or "")
            visual_payload = self._extract_visual_payload(payload, content_type)
            image_hint = bool(visual_payload)
            matched_families = self._match_families("http", " ".join([content_type, path]))
            saved_path = self._save_snapshot(ip, port, path, visual_payload, content_type) if image_hint and visual_payload else ""
            payload_sha256 = hashlib.sha256(visual_payload).hexdigest() if visual_payload else ""
            return {
                "ok": True,
                "scheme": "https" if use_tls else "http",
                "port": port,
                "path": path,
                "status": int(response.status),
                "reason": str(response.reason),
                "content_type": content_type,
                "content_length": int(headers.get("content-length") or 0) if str(headers.get("content-length") or "").isdigit() else len(payload),
                "image_hint": image_hint,
                "saved_path": saved_path,
                "payload_sha256": payload_sha256,
                "matched_families": matched_families[:6],
                "latency_ms": round((time.time() - started) * 1000, 1),
            }
        except Exception as exc:
            return {"ok": False, "scheme": "https" if use_tls else "http", "port": port, "path": path, "error": str(exc)}
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    @staticmethod
    def _payload_looks_like_image(payload: bytes, content_type: str) -> bool:
        lowered = str(content_type or "").lower()
        if lowered.startswith("image/"):
            return True
        if "multipart/x-mixed-replace" in lowered or "multipart/mixed" in lowered:
            return b"\xff\xd8\xff" in payload or b"\x89PNG\r\n\x1a\n" in payload
        if payload.startswith(b"\xff\xd8\xff"):
            return True
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            return True
        if payload.startswith(b"RIFF") and payload[8:12] == b"WEBP":
            return True
        if payload.startswith(b"BM"):
            return True
        return False

    def _extract_visual_payload(self, payload: bytes, content_type: str) -> bytes:
        if not payload:
            return b""
        if self._payload_looks_like_image(payload, content_type):
            multipart_frame = self._extract_multipart_frame(payload)
            if multipart_frame:
                return multipart_frame
            direct_frame = self._extract_direct_image(payload)
            if direct_frame:
                return direct_frame
        return b""

    @staticmethod
    def _extract_multipart_frame(payload: bytes) -> bytes:
        jpeg_start = payload.find(b"\xff\xd8\xff")
        if jpeg_start >= 0:
            jpeg_end = payload.find(b"\xff\xd9", jpeg_start + 3)
            if jpeg_end > jpeg_start:
                return payload[jpeg_start : jpeg_end + 2]
        png_start = payload.find(b"\x89PNG\r\n\x1a\n")
        if png_start >= 0:
            iend = payload.find(b"IEND", png_start + 8)
            if iend > png_start and iend + 8 <= len(payload):
                return payload[png_start : iend + 8]
        return b""

    @staticmethod
    def _extract_direct_image(payload: bytes) -> bytes:
        if payload.startswith(b"\xff\xd8\xff"):
            jpeg_end = payload.find(b"\xff\xd9", 3)
            return payload if jpeg_end < 0 else payload[: jpeg_end + 2]
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            iend = payload.find(b"IEND", 8)
            return payload if iend < 0 else payload[: iend + 8]
        if payload.startswith(b"RIFF") and payload[8:12] == b"WEBP":
            return payload
        if payload.startswith(b"BM"):
            return payload
        return b""

    def _save_snapshot(self, ip: str, port: int, path: str, payload: bytes, content_type: str) -> str:
        extension = ".jpg"
        lowered = str(content_type or "").lower()
        if "png" in lowered:
            extension = ".png"
        elif "bmp" in lowered:
            extension = ".bmp"
        elif "webp" in lowered:
            extension = ".webp"
        elif payload.startswith(b"\x89PNG\r\n\x1a\n"):
            extension = ".png"
        elif payload.startswith(b"RIFF") and payload[8:12] == b"WEBP":
            extension = ".webp"
        elif payload.startswith(b"BM"):
            extension = ".bmp"
        safe_ip = str(ip).replace(":", "_").replace(".", "_")
        safe_path = str(path or "snapshot").strip("/").replace("/", "_").replace("?", "_").replace("=", "_").replace("&", "_") or "snapshot"
        filename = f"{time.strftime('%Y%m%d_%H%M%S')}_{safe_ip}_{port}_{safe_path}{extension}"
        target = self.image_dir / filename
        self.image_dir.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return str(target)

    def _save_protocol_artifact(self, *, ip: str, port: int, protocol: str, suffix: str, payload: bytes, extension: str = ".txt") -> str:
        safe_ip = str(ip).replace(":", "_").replace(".", "_")
        safe_suffix = str(suffix or protocol).replace("/", "_").replace(" ", "_")
        filename = f"{time.strftime('%Y%m%d_%H%M%S')}_{safe_ip}_{port}_{safe_suffix}{extension}"
        target = self.protocol_dir / filename
        self.protocol_dir.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return str(target)

    def _capture_rtsp_frame(self, *, ip: str, port: int, matched_families: List[Dict[str, Any]], root_describe_ok: bool) -> Dict[str, Any]:
        if not self.ffmpeg_path:
            return {"ok": False, "error": "ffmpeg_unavailable"}
        for url in self._rtsp_candidate_urls(ip=ip, port=port, matched_families=matched_families, root_describe_ok=root_describe_ok):
            target = self._rtsp_frame_target(ip=ip, port=port, url=url)
            try:
                result = subprocess.run(
                    [
                        self.ffmpeg_path,
                        "-hide_banner",
                        "-loglevel",
                        "error",
                        "-y",
                        "-rtsp_transport",
                        "tcp",
                        "-i",
                        url,
                        "-frames:v",
                        "1",
                        "-q:v",
                        "2",
                        str(target),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=max(5.0, self.timeout_seconds + 5.0),
                    check=False,
                )
            except Exception as exc:
                return {"ok": False, "error": str(exc), "url": url}
            if result.returncode == 0 and target.exists() and target.stat().st_size > 0:
                return {"ok": True, "saved_path": str(target), "url": url}
            try:
                if target.exists():
                    target.unlink()
            except OSError:
                pass
        return {"ok": False, "error": "no_rtsp_frame_recovered"}

    def _rtsp_candidate_urls(self, *, ip: str, port: int, matched_families: List[Dict[str, Any]], root_describe_ok: bool) -> List[str]:
        family_tokens = {str(item.get("family") or "").strip().lower() for item in matched_families if str(item.get("family") or "").strip()}
        paths = list(self.RTSP_PATHS)
        if "hikvision" in family_tokens:
            paths = ["/Streaming/Channels/101", "/Streaming/Channels/1", *paths]
        if "dahua" in family_tokens:
            paths = ["/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1", *paths]
        if "reolink" in family_tokens:
            paths = ["/h264Preview_01_main", "/h264Preview_01_sub", *paths]
        if "axis" in family_tokens:
            paths = ["/axis-media/media.amp", *paths]
        if root_describe_ok:
            paths = ["/", *paths]
        urls: List[str] = []
        for raw_path in paths:
            path = str(raw_path or "/").strip() or "/"
            url = f"rtsp://{ip}:{port}{path}" if path.startswith("/") else f"rtsp://{ip}:{port}/{path}"
            if url not in urls:
                urls.append(url)
        return urls[:8]

    def _rtsp_frame_target(self, *, ip: str, port: int, url: str) -> Path:
        safe_ip = str(ip).replace(":", "_").replace(".", "_")
        safe_suffix = re.sub(r"[^a-zA-Z0-9._-]+", "_", url.split(f"{ip}:{port}", 1)[-1].strip("/") or "root")
        filename = f"{time.strftime('%Y%m%d_%H%M%S')}_{safe_ip}_{port}_{safe_suffix}.jpg"
        self.image_dir.mkdir(parents=True, exist_ok=True)
        return self.image_dir / filename

    def _rtsp_exchange(self, ip: str, port: int, request: str) -> Dict[str, Any]:
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((ip, port), timeout=self.timeout_seconds)
            sock.settimeout(self.timeout_seconds)
            sock.sendall(request.encode("ascii", errors="ignore"))
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            return {"ok": True, "response": response}
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    @staticmethod
    def _header_value(payload: str, header_name: str) -> str:
        prefix = f"{header_name.lower()}:"
        for line in str(payload or "").splitlines():
            if line.lower().startswith(prefix):
                return line.split(":", 1)[1].strip()
        return ""

    def _route_interface(self, ip: str) -> str:
        try:
            result = subprocess.run(
                ["ip", "route", "get", ip],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        except Exception:
            return ""
        if result.returncode != 0:
            return ""
        tokens = (result.stdout or "").split()
        for index, token in enumerate(tokens):
            if token == "dev" and index + 1 < len(tokens):
                return tokens[index + 1].strip()
        return ""

    def _default_route_interface(self) -> str:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        except Exception:
            return ""
        if result.returncode != 0:
            return ""
        tokens = (result.stdout or "").split()
        for index, token in enumerate(tokens):
            if token == "dev" and index + 1 < len(tokens):
                return tokens[index + 1].strip()
        return ""

    def _interface_subnet(self, interface: str) -> str:
        iface = str(interface or "").strip()
        if not iface:
            return ""
        for command in (
            ["ip", "route", "show", "dev", iface, "scope", "link"],
            ["ip", "-4", "addr", "show", "dev", iface],
        ):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=max(1.0, self.timeout_seconds),
                    check=False,
                )
            except Exception:
                continue
            if result.returncode != 0:
                continue
            for raw in (result.stdout or "").splitlines():
                line = raw.strip()
                if not line:
                    continue
                if command[1:4] == ["route", "show", "dev"]:
                    first = line.split()[0]
                    if "/" in first:
                        return first
                else:
                    match = re.search(r"\binet\s+([0-9.]+/\d+)", line)
                    if match:
                        return str(match.group(1) or "").strip()
        return ""

    def _validate_route_interface(self, ip: str, *, route_interface: str = "") -> Dict[str, Any]:
        active_interface = str(route_interface or self._route_interface(ip) or self._default_route_interface() or "").strip()
        if not active_interface:
            return {"ok": False, "error": "Unable to determine the route interface for active validation.", "route_interface": ""}
        return {"ok": True, "route_interface": active_interface}

    def _match_families(self, protocol: str, payload: str) -> List[Dict[str, Any]]:
        haystack = str(payload or "").lower()
        matches: List[Dict[str, Any]] = []
        if not haystack.strip():
            return matches
        for signature in CAMERA_SIGNATURE_DATABASE:
            family = str(signature.get("family") or "").strip()
            if not family:
                continue
            tokens = []
            if protocol == "http":
                tokens.extend(signature.get("http_probe_keywords") or [])
                tokens.extend(signature.get("http_server_keywords") or [])
                tokens.extend(signature.get("http_auth_keywords") or [])
            elif protocol == "onvif":
                tokens.extend(signature.get("onvif_keywords") or [])
            elif protocol == "rtsp":
                tokens.extend(signature.get("rtsp_server_keywords") or [])
            tokens.extend(signature.get("brands") or [])
            tokens.extend(signature.get("hostname_keywords") or [])
            tokens.extend(signature.get("cert_keywords") or [])
            matched_tokens = sorted({token for token in tokens if token and str(token).lower() in haystack})
            if matched_tokens:
                matches.append(
                    {
                        "family": family,
                        "score": len(matched_tokens) + int(signature.get("confidence_bias") or 0),
                        "tokens": matched_tokens[:6],
                    }
                )
        return sorted(matches, key=lambda item: (int(item.get("score") or 0), item.get("family") or ""), reverse=True)[:6]

    @staticmethod
    def _merge_family_matches(*groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for group in groups:
            for match in group or []:
                family = str(match.get("family") or "").strip()
                if not family:
                    continue
                current = merged.setdefault(family, {"family": family, "score": 0, "tokens": []})
                current["score"] = max(int(current.get("score") or 0), int(match.get("score") or 0))
                current["tokens"] = sorted({*list(current.get("tokens") or []), *list(match.get("tokens") or [])})[:6]
        return sorted(merged.values(), key=lambda item: (int(item.get("score") or 0), item.get("family") or ""), reverse=True)

    def _summarize(self, probes: List[Dict[str, Any]]) -> Dict[str, Any]:
        http_hits = 0
        onvif_hits = 0
        rtsp_hits = 0
        rtsp_frame_hits = 0
        snapshot_hits = 0
        visual_artifacts: List[Dict[str, Any]] = []
        matched_families: List[Dict[str, Any]] = []
        for result in probes:
            ip = str(result.get("ip") or "").strip()
            rtsp = result.get("rtsp") or {}
            snapshot = result.get("snapshot") or {}
            if bool(((result.get("http") or {}).get("camera_hint"))):
                http_hits += 1
            if bool(((result.get("onvif") or {}).get("camera_hint"))):
                onvif_hits += 1
            if bool(rtsp.get("camera_hint")):
                rtsp_hits += 1
            if rtsp.get("frame_capture_path"):
                rtsp_frame_hits += 1
                visual_artifacts.append(
                    {
                        "source": "rtsp_probe",
                        "protocol": "rtsp",
                        "ip": ip,
                        "url": rtsp.get("frame_capture_url") or "",
                        "path": rtsp.get("frame_capture_path") or "",
                    }
                )
            if bool(snapshot.get("image_hint")):
                snapshot_hits += 1
            for finding in snapshot.get("findings") or []:
                saved_path = str(finding.get("saved_path") or "").strip()
                if not saved_path:
                    continue
                scheme = str(finding.get("scheme") or "http").strip() or "http"
                port = finding.get("port") or ""
                path = str(finding.get("path") or "").strip()
                visual_artifacts.append(
                    {
                        "source": "snapshot_probe",
                        "protocol": scheme,
                        "ip": ip,
                        "url": f"{scheme}://{ip}:{port}{path}" if ip and port and path else "",
                        "path": saved_path,
                        "payload_sha256": finding.get("payload_sha256") or "",
                    }
                )
            matched_families = self._merge_family_matches(
                matched_families,
                (result.get("http") or {}).get("matched_families") or [],
                (result.get("onvif") or {}).get("matched_families") or [],
                (result.get("rtsp") or {}).get("matched_families") or [],
                (result.get("snapshot") or {}).get("matched_families") or [],
            )
        camera_positive = bool(http_hits or onvif_hits or rtsp_hits or snapshot_hits)
        visual_artifacts = [artifact for artifact in visual_artifacts if artifact.get("path")]
        video_or_image_proof = bool(visual_artifacts)
        if video_or_image_proof:
            proof_level = "VISUAL_ARTIFACT"
        elif snapshot_hits or (onvif_hits and rtsp_hits):
            proof_level = "LOCAL_CAMERA_SERVICE"
        elif http_hits or onvif_hits or rtsp_hits:
            proof_level = "SERVICE_HINT_ONLY"
        else:
            proof_level = "NO_PROOF"
        if video_or_image_proof:
            camera_positive_summary = "A live image endpoint or RTSP stream produced a retained visual artifact; treat this as camera-positive proof pending visual review."
        elif snapshot_hits:
            camera_positive_summary = "A live image endpoint answered with an image payload, but no visual artifact path was retained; rerun probe or review artifact permissions."
        elif onvif_hits and rtsp_hits:
            camera_positive_summary = "ONVIF and RTSP both answered; treat this as strong local-camera service confirmation, but not visual proof."
        elif onvif_hits:
            camera_positive_summary = "ONVIF answered from an inferred candidate IP; treat this as camera or NVR-class service evidence, but not visual proof."
        elif rtsp_hits:
            camera_positive_summary = "RTSP answered from an inferred candidate IP; treat this as stream-capable service evidence, but not visual proof."
        elif http_hits:
            camera_positive_summary = "HTTP fingerprinting returned camera-like headers or auth prompts; merge with passive evidence before promotion."
        else:
            camera_positive_summary = "No strong camera-positive probe evidence returned from inferred candidate IPs."
        return {
            "http_hits": http_hits,
            "onvif_hits": onvif_hits,
            "rtsp_hits": rtsp_hits,
            "rtsp_frame_hits": rtsp_frame_hits,
            "snapshot_hits": snapshot_hits,
            "camera_positive": camera_positive,
            "matched_families": matched_families[:6],
            "visual_artifact_count": len(visual_artifacts),
            "visual_artifacts": visual_artifacts[:12],
            "video_or_image_proof": video_or_image_proof,
            "proof_level": proof_level,
            "camera_positive_summary": camera_positive_summary,
        }
