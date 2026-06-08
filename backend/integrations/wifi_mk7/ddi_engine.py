from __future__ import annotations

import subprocess
import socket
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


class WiFiDDIEngine:
    VERSION = "2026-04-20-v1"

    def __init__(self, tshark_path: str | None = None) -> None:
        self.tshark_path = str(tshark_path or "").strip()
        self._session_cache_signature = ""
        self._session_cache: Dict[str, Any] = {}

    @staticmethod
    def _normalize_mac(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _normalize_ip(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw or ":" in raw:
            return ""
        parts = raw.split(".")
        if len(parts) != 4:
            return ""
        try:
            octets = [int(item) for item in parts]
        except Exception:
            return ""
        if any(item < 0 or item > 255 for item in octets):
            return ""
        return raw

    @staticmethod
    def _looks_private(ip_value: str) -> bool:
        value = str(ip_value or "").strip()
        return value.startswith("10.") or value.startswith("192.168.") or value.startswith("172.")

    @staticmethod
    def _confidence_label(score: float) -> str:
        if score >= 0.85:
            return "HIGH"
        if score >= 0.65:
            return "MEDIUM"
        if score >= 0.35:
            return "LOW"
        return "UNSUPPORTED"

    @staticmethod
    def _result_record(*, test_id: str, test_type: str, target: str, method: str, result: str, evidence: List[Dict[str, Any]], explanation: str) -> Dict[str, Any]:
        return {
            "test_id": test_id,
            "test_type": test_type,
            "target": target,
            "method": method,
            "result": result,
            "evidence": evidence,
            "explanation": explanation,
        }

    @staticmethod
    def _target_id(target: Dict[str, Any]) -> str:
        if str(target.get("mac") or "").strip():
            return f"client:{str(target.get('mac') or '').strip().lower()}"
        return f"network:{str(target.get('bssid') or target.get('record_id') or '').strip().lower()}"

    @staticmethod
    def _mac_candidates(target: Dict[str, Any]) -> List[str]:
        values = {
            str(target.get("mac") or "").strip().lower(),
            str(target.get("bssid") or "").strip().lower(),
            str(target.get("associated_bssid") or "").strip().lower(),
            str(((target.get("associated_network") or {}).get("bssid") or "")).strip().lower(),
        }
        return [value for value in values if value and ":" in value]

    @staticmethod
    def _inventory_signature(pcap_inventory: List[Dict[str, Any]]) -> str:
        parts: List[str] = []
        for entry in pcap_inventory or []:
            path = Path(str(entry.get("path") or "").strip())
            if not path.exists():
                continue
            try:
                stat = path.stat()
                parts.append(f"{path}:{int(stat.st_mtime)}:{int(stat.st_size)}")
            except Exception:
                parts.append(str(path))
        return "|".join(parts)

    def _parse_session_pcaps(self, pcap_inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        cache = {
            "dhcp_by_mac": defaultdict(list),
            "arp_sender_by_mac": defaultdict(list),
            "arp_target_by_mac": defaultdict(list),
            "ip_src_by_mac": defaultdict(list),
            "ip_dst_by_mac": defaultdict(list),
            "host_hints_by_mac": defaultdict(list),
            "subnets_by_bssid": defaultdict(Counter),
            "frame_count": 0,
        }
        if not self.tshark_path:
            return cache
        for entry in pcap_inventory or []:
            pcap_path = str(entry.get("path") or "").strip()
            if not pcap_path or not Path(pcap_path).exists():
                continue
            command = [
                self.tshark_path,
                "-r",
                pcap_path,
                "-Y",
                "bootp or arp or ip",
                "-T",
                "fields",
                "-E",
                "header=n",
                "-E",
                "separator=\t",
                "-E",
                "occurrence=a",
                "-e",
                "frame.number",
                "-e",
                "frame.time_epoch",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.da",
                "-e",
                "wlan.bssid",
                "-e",
                "eth.src",
                "-e",
                "eth.dst",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "arp.src.proto_ipv4",
                "-e",
                "arp.dst.proto_ipv4",
                "-e",
                "arp.src.hw_mac",
                "-e",
                "arp.dst.hw_mac",
                "-e",
                "bootp.hw.mac_addr",
                "-e",
                "bootp.option.dhcp",
                "-e",
                "bootp.yiaddr",
                "-e",
                "bootp.option.hostname",
                "-e",
                "bootp.option.vendor_class_id",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.ptr.domain_name",
                "-e",
                "http.host",
            ]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
            except Exception:
                continue
            if result.returncode != 0:
                continue
            for raw in (result.stdout or "").splitlines():
                if not raw.strip():
                    continue
                parts = raw.split("\t")
                while len(parts) < 21:
                    parts.append("")
                (
                    frame_number,
                    ts_text,
                    wlan_sa,
                    wlan_da,
                    wlan_bssid,
                    eth_src,
                    eth_dst,
                    ip_src,
                    ip_dst,
                    arp_src_ip,
                    arp_dst_ip,
                    arp_src_mac,
                    arp_dst_mac,
                    dhcp_mac,
                    dhcp_type,
                    dhcp_yiaddr,
                    dhcp_hostname,
                    dhcp_vendor_class,
                    dns_qry_name,
                    dns_ptr_name,
                    http_host,
                ) = parts[:21]
                try:
                    timestamp = float(ts_text or 0.0)
                except Exception:
                    timestamp = 0.0
                ref = {
                    "pcap_file": pcap_path,
                    "frame_number": int(frame_number or 0),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)) if timestamp else "",
                }
                cache["frame_count"] += 1

                bssid = self._normalize_mac(wlan_bssid)
                src_mac = self._normalize_mac(wlan_sa or eth_src)
                dst_mac = self._normalize_mac(wlan_da or eth_dst)
                normalized_ip_src = self._normalize_ip(ip_src)
                normalized_ip_dst = self._normalize_ip(ip_dst)
                arp_src_mac_norm = self._normalize_mac(arp_src_mac or src_mac)
                arp_dst_mac_norm = self._normalize_mac(arp_dst_mac or dst_mac)
                arp_src_ip_norm = self._normalize_ip(arp_src_ip)
                arp_dst_ip_norm = self._normalize_ip(arp_dst_ip)
                dhcp_mac_norm = self._normalize_mac(dhcp_mac)
                dhcp_ip_norm = self._normalize_ip(dhcp_yiaddr)
                if dhcp_mac_norm and dhcp_ip_norm:
                    cache["dhcp_by_mac"][dhcp_mac_norm].append(
                        {
                            "candidate_ip": dhcp_ip_norm,
                            "dhcp_type": str(dhcp_type or "").strip().lower(),
                            "hostname": str(dhcp_hostname or "").strip(),
                            "vendor_class": str(dhcp_vendor_class or "").strip(),
                            "bssid": bssid,
                            "evidence": ref,
                        }
                    )
                    if bssid and self._looks_private(dhcp_ip_norm):
                        subnet = ".".join(dhcp_ip_norm.split(".")[:3])
                        cache["subnets_by_bssid"][bssid][subnet] += 1
                if arp_src_mac_norm and arp_src_ip_norm:
                    cache["arp_sender_by_mac"][arp_src_mac_norm].append(
                        {
                            "candidate_ip": arp_src_ip_norm,
                            "peer_ip": arp_dst_ip_norm,
                            "bssid": bssid,
                            "evidence": ref,
                        }
                    )
                    if bssid and self._looks_private(arp_src_ip_norm):
                        subnet = ".".join(arp_src_ip_norm.split(".")[:3])
                        cache["subnets_by_bssid"][bssid][subnet] += 1
                if arp_dst_mac_norm and arp_dst_ip_norm:
                    cache["arp_target_by_mac"][arp_dst_mac_norm].append(
                        {
                            "candidate_ip": arp_dst_ip_norm,
                            "peer_ip": arp_src_ip_norm,
                            "bssid": bssid,
                            "evidence": ref,
                        }
                    )
                if src_mac and normalized_ip_src:
                    cache["ip_src_by_mac"][src_mac].append(
                        {
                            "candidate_ip": normalized_ip_src,
                            "peer_ip": normalized_ip_dst,
                            "bssid": bssid,
                            "evidence": ref,
                        }
                    )
                    if bssid and self._looks_private(normalized_ip_src):
                        subnet = ".".join(normalized_ip_src.split(".")[:3])
                        cache["subnets_by_bssid"][bssid][subnet] += 1
                if dst_mac and normalized_ip_dst:
                    cache["ip_dst_by_mac"][dst_mac].append(
                        {
                            "candidate_ip": normalized_ip_dst,
                            "peer_ip": normalized_ip_src,
                            "bssid": bssid,
                            "evidence": ref,
                        }
                    )
                for mac_value in {dhcp_mac_norm, src_mac, dst_mac, arp_src_mac_norm, arp_dst_mac_norm}:
                    if not mac_value:
                        continue
                    hints = cache["host_hints_by_mac"][mac_value]
                    for hint_type, hint_value in (
                        ("DHCP_HOSTNAME", dhcp_hostname),
                        ("DHCP_VENDOR_CLASS", dhcp_vendor_class),
                        ("DNS_QUERY", dns_qry_name),
                        ("MDNS_PTR", dns_ptr_name),
                        ("HTTP_HOST", http_host),
                    ):
                        cleaned = str(hint_value or "").strip()
                        if cleaned:
                            hints.append({"type": hint_type, "value": cleaned, "evidence": ref})
        return cache

    def _session_data(self, pcap_inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        signature = self._inventory_signature(pcap_inventory)
        if signature == self._session_cache_signature:
            return self._session_cache
        self._session_cache_signature = signature
        self._session_cache = self._parse_session_pcaps(pcap_inventory)
        return self._session_cache

    @staticmethod
    def _neighbor_sources(macs: List[str]) -> List[Dict[str, Any]]:
        known = {str(item or "").strip().lower() for item in macs if str(item or "").strip()}
        rows: List[Dict[str, Any]] = []
        if not known:
            return rows
        arp_path = Path("/proc/net/arp")
        try:
            if arp_path.exists():
                for raw in arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                    parts = raw.split()
                    if len(parts) >= 4 and str(parts[3]).strip().lower() in known:
                        rows.append(
                            {
                                "candidate_ip": str(parts[0]).strip(),
                                "neighbor_mac": str(parts[3]).strip().lower(),
                                "method": "/proc/net/arp",
                            }
                        )
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["/usr/sbin/ip", "neigh"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            for raw in (result.stdout or "").splitlines():
                parts = raw.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        mac_value = str(parts[idx + 1]).strip().lower()
                        if mac_value in known:
                            rows.append(
                                {
                                    "candidate_ip": str(parts[0]).strip(),
                                    "neighbor_mac": mac_value,
                                    "method": "ip neigh",
                                }
                            )
        except Exception:
            pass
        return rows

    def _safe_connect_validation(self, ip_value: str, ports: List[int] | None = None) -> Dict[str, Any]:
        if not self._looks_private(ip_value):
            return {"validated": False, "method": "safe_connect_validation", "port": 0, "explanation": "Candidate IP was not private."}
        for port in ports or [80, 443, 554, 8080, 8443, 22]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.2)
            try:
                if sock.connect_ex((ip_value, int(port))) == 0:
                    return {
                        "validated": True,
                        "method": "safe_connect_validation",
                        "port": int(port),
                        "explanation": f"Safe TCP connect validation succeeded on {ip_value}:{int(port)}.",
                    }
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        return {"validated": False, "method": "safe_connect_validation", "port": 0, "explanation": f"No safe connect validation succeeded for {ip_value}."}

    @staticmethod
    def _target_hint_candidates(target: Dict[str, Any]) -> List[Tuple[str, str, float, str]]:
        stable = dict(target.get("stable_fingerprint") or {})
        candidates: List[Tuple[str, str, float, str]] = []
        for value in (
            target.get("ip"),
            target.get("ip_address"),
            target.get("local_ip"),
        ):
            cleaned = str(value or "").strip()
            if cleaned:
                candidates.append((cleaned, "TARGET_FIELD", 0.52, "Target retained a direct local IP hint."))
        for value in list((stable.get("dhcp_assigned_ips") or [])):
            cleaned = str(value or "").strip()
            if cleaned:
                candidates.append((cleaned, "STABLE_DHCP_HINT", 0.68, "Stable fingerprint retained DHCP-assigned IP evidence."))
        for value in list((stable.get("related_ips") or [])):
            cleaned = str(value or "").strip()
            if cleaned:
                candidates.append((cleaned, "RELATED_IP_HINT", 0.44, "Stable fingerprint retained related IP evidence."))
        for value in list((stable.get("recurring_destination_ips") or {}).keys()):
            cleaned = str(value or "").strip()
            if cleaned:
                candidates.append((cleaned, "RECURRING_IP_HINT", 0.28, "Recurring retained destination IPs suggested this local candidate."))
        for value in list((stable.get("associated_network_recurring_ips") or {}).keys()):
            cleaned = str(value or "").strip()
            if cleaned:
                candidates.append((cleaned, "ASSOCIATED_NETWORK_IP_HINT", 0.3, "Associated network recurring IP evidence suggested this candidate."))
        for value in list(((target.get("active_fingerprint") or {}).get("candidate_ips") or [])):
            cleaned = str(value or "").strip()
            if cleaned:
                candidates.append((cleaned, "ACTIVE_PROBE_HINT", 0.58, "Retained active fingerprint candidate IP suggested this local target."))
        return candidates

    def resolve_target(self, target: Dict[str, Any], pcap_inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        target_id = self._target_id(target)
        macs = self._mac_candidates(target)
        session = self._session_data(pcap_inventory)
        candidates: Dict[str, Dict[str, Any]] = {}
        test_trace: List[Dict[str, Any]] = []
        negative_evidence: List[Dict[str, Any]] = []
        contradictions: List[Dict[str, Any]] = []
        associated_bssid = self._normalize_mac(target.get("associated_bssid") or ((target.get("associated_network") or {}).get("bssid") or target.get("bssid")))

        def ensure_candidate(ip_value: str) -> Dict[str, Any]:
            record = candidates.setdefault(
                ip_value,
                {
                    "target_id": target_id,
                    "mac": str(target.get("mac") or target.get("bssid") or "").strip().lower(),
                    "candidate_ip": ip_value,
                    "source_types": set(),
                    "confidence_score": 0.0,
                    "evidence": [],
                    "first_seen": "",
                    "last_seen": "",
                    "status": "CANDIDATE",
                    "host_hints": [],
                },
            )
            return record

        def add_evidence(ip_value: str, *, source_type: str, weight: float, evidence: Dict[str, Any], explanation: str, hint: str = "") -> None:
            normalized_ip = self._normalize_ip(ip_value)
            if not normalized_ip:
                return
            record = ensure_candidate(normalized_ip)
            record["source_types"].add(source_type)
            record["confidence_score"] = min(0.99, float(record.get("confidence_score") or 0.0) + weight)
            record["evidence"].append({**evidence, "method": source_type.lower(), "explanation": explanation})
            timestamp = str(evidence.get("timestamp") or "")
            if timestamp:
                if not record.get("first_seen") or timestamp < str(record.get("first_seen") or ""):
                    record["first_seen"] = timestamp
                if not record.get("last_seen") or timestamp > str(record.get("last_seen") or ""):
                    record["last_seen"] = timestamp
            if hint:
                host_hints = list(record.get("host_hints") or [])
                if hint not in host_hints:
                    host_hints.append(hint)
                    record["host_hints"] = host_hints[:8]

        dhcp_events = []
        arp_sender_events = []
        arp_target_events = []
        ip_src_events = []
        ip_dst_events = []
        host_hints = []
        for mac in macs:
            dhcp_events.extend(list(session.get("dhcp_by_mac", {}).get(mac) or []))
            arp_sender_events.extend(list(session.get("arp_sender_by_mac", {}).get(mac) or []))
            arp_target_events.extend(list(session.get("arp_target_by_mac", {}).get(mac) or []))
            ip_src_events.extend(list(session.get("ip_src_by_mac", {}).get(mac) or []))
            ip_dst_events.extend(list(session.get("ip_dst_by_mac", {}).get(mac) or []))
            host_hints.extend(list(session.get("host_hints_by_mac", {}).get(mac) or []))
        for ip_value, source_type, weight, explanation in self._target_hint_candidates(target):
            add_evidence(
                ip_value,
                source_type=source_type,
                weight=weight,
                evidence={"pcap_file": "", "frame_number": 0, "timestamp": "", "method": source_type.lower()},
                explanation=explanation,
            )

        if not dhcp_events:
            negative_evidence.append(
                self._result_record(
                    test_id="ddi_validate_001",
                    test_type="dhcp_ip_materialization",
                    target=target_id,
                    method="pcap_dhcp_ack_parse",
                    result="NOT_OBSERVED",
                    evidence=[],
                    explanation="No DHCP evidence attributable to the target MAC was observed during the retained capture window.",
                )
            )
        for event in dhcp_events:
            dhcp_type = str(event.get("dhcp_type") or "").lower()
            weight = 0.72 if "ack" in dhcp_type or dhcp_type == "5" else 0.62 if "offer" in dhcp_type or dhcp_type == "2" else 0.48
            result_label = "VALIDATED" if weight >= 0.72 else "CANDIDATE"
            add_evidence(
                event.get("candidate_ip") or "",
                source_type="DHCP_ACK" if weight >= 0.72 else "DHCP_EVIDENCE",
                weight=weight,
                evidence=event.get("evidence") or {},
                explanation=f"DHCP evidence assigned {event.get('candidate_ip')} to target MAC {macs[0] if macs else ''}.",
                hint=str(event.get("hostname") or ""),
            )
            test_trace.append(
                self._result_record(
                    test_id="ddi_validate_002",
                    test_type="dhcp_ip_materialization",
                    target=target_id,
                    method="pcap_dhcp_ack_parse",
                    result=result_label,
                    evidence=[event.get("evidence") or {}],
                    explanation=f"DHCP {dhcp_type or 'assignment'} linked {event.get('candidate_ip')} to the target MAC.",
                )
            )

        if not arp_sender_events:
            negative_evidence.append(
                self._result_record(
                    test_id="ddi_validate_003",
                    test_type="arp_correlation_check",
                    target=target_id,
                    method="pcap_arp_extract",
                    result="NOT_OBSERVED",
                    evidence=[],
                    explanation="No ARP sender-IP correlation attributable to the target MAC was observed during the retained capture window.",
                )
            )
        for event in arp_sender_events:
            add_evidence(
                event.get("candidate_ip") or "",
                source_type="ARP_SENDER",
                weight=0.64,
                evidence=event.get("evidence") or {},
                explanation=f"ARP sender MAC matched the target and asserted {event.get('candidate_ip')}.",
            )
        for event in arp_target_events:
            add_evidence(
                event.get("candidate_ip") or "",
                source_type="ARP_TARGET",
                weight=0.38,
                evidence=event.get("evidence") or {},
                explanation=f"ARP target MAC matched the target while referencing {event.get('candidate_ip')}.",
            )

        if not ip_src_events and not ip_dst_events:
            negative_evidence.append(
                self._result_record(
                    test_id="ddi_validate_004",
                    test_type="ip_packet_correlation",
                    target=target_id,
                    method="pcap_ip_extract",
                    result="NOT_OBSERVED",
                    evidence=[],
                    explanation="No IP-layer packets attributable to the target MAC were observed during the retained capture window.",
                )
            )
        ip_src_counts = Counter(self._normalize_ip(item.get("candidate_ip")) for item in ip_src_events if self._normalize_ip(item.get("candidate_ip")))
        ip_dst_counts = Counter(self._normalize_ip(item.get("candidate_ip")) for item in ip_dst_events if self._normalize_ip(item.get("candidate_ip")))
        for event in ip_src_events:
            count = max(1, int(ip_src_counts.get(self._normalize_ip(event.get("candidate_ip")), 1)))
            add_evidence(
                event.get("candidate_ip") or "",
                source_type="IP_SRC",
                weight=min(0.62, 0.32 + (count * 0.06)),
                evidence=event.get("evidence") or {},
                explanation=f"Repeated IP source correlation tied the target MAC to source IP {event.get('candidate_ip')}.",
            )
        for event in ip_dst_events:
            count = max(1, int(ip_dst_counts.get(self._normalize_ip(event.get("candidate_ip")), 1)))
            add_evidence(
                event.get("candidate_ip") or "",
                source_type="IP_DST",
                weight=min(0.42, 0.18 + (count * 0.04)),
                evidence=event.get("evidence") or {},
                explanation=f"Observed packets addressed to the target MAC also addressed IP {event.get('candidate_ip')}.",
            )

        neighbor_rows = self._neighbor_sources(macs)
        if not neighbor_rows:
            negative_evidence.append(
                self._result_record(
                    test_id="ddi_validate_005",
                    test_type="neighbor_table_check",
                    target=target_id,
                    method="host_neighbor_lookup",
                    result="NOT_OBSERVED",
                    evidence=[],
                    explanation="No neighbor-table entry tied the target MAC to an IP on the host.",
                )
            )
        for row in neighbor_rows:
            add_evidence(
                row.get("candidate_ip") or "",
                source_type="NEIGHBOR_TABLE",
                weight=0.54,
                evidence={"pcap_file": "", "frame_number": 0, "timestamp": "", "method": row.get("method") or ""},
                explanation=f"Host neighbor state tied the target MAC to IP {row.get('candidate_ip')}.",
            )

        if associated_bssid:
            subnets = session.get("subnets_by_bssid", {}).get(associated_bssid) or {}
            if subnets:
                strongest_subnet = next(iter(Counter(subnets).most_common(1)), ("", 0))[0]
                if strongest_subnet:
                    for candidate_ip, record in list(candidates.items()):
                        if candidate_ip.startswith(f"{strongest_subnet}."):
                            record["confidence_score"] = min(0.99, float(record.get("confidence_score") or 0.0) + 0.08)
                    test_trace.append(
                        self._result_record(
                            test_id="ddi_validate_006",
                            test_type="ap_subnet_context",
                            target=target_id,
                            method="associated_ap_subnet_inference",
                            result="CANDIDATE",
                            evidence=[],
                            explanation=f"Associated AP context suggested subnet {strongest_subnet}.0/24 for corroboration only.",
                        )
                    )

        if not candidates:
            explanation = "No validated IP. DHCP was not observed, ARP correlation absent, and no attributable IP packets or neighbor-table matches were retained."
            return {
                "target_id": target_id,
                "mac": str(target.get("mac") or target.get("bssid") or "").strip().lower(),
                "associated_bssid": associated_bssid,
                "candidate_ips": [],
                "validated_candidates": [],
                "rejected_candidates": [],
                "contradictory_evidence": [],
                "confidence_summary": {"highest_score": 0.0, "highest_confidence": "UNSUPPORTED"},
                "resolution_state": "NO_IP_EVIDENCE",
                "explanation": explanation,
                "evidence": [],
                "negative_evidence": negative_evidence,
                "test_trace": test_trace,
                "first_seen": "",
                "last_seen": "",
            }

        candidate_rows: List[Dict[str, Any]] = []
        for ip_value, record in candidates.items():
            source_types = sorted(record.get("source_types") or [])
            score = float(record.get("confidence_score") or 0.0)
            if len(source_types) >= 2:
                score = min(0.99, score + 0.08)
            evidence_rows = list(record.get("evidence") or [])
            candidate_rows.append(
                {
                    "target_id": target_id,
                    "mac": str(record.get("mac") or ""),
                    "candidate_ip": ip_value,
                    "source_type": source_types[0] if source_types else "UNSUPPORTED",
                    "source_types": source_types,
                    "confidence": self._confidence_label(score),
                    "confidence_score": round(score, 2),
                    "first_seen": record.get("first_seen") or "",
                    "last_seen": record.get("last_seen") or "",
                    "evidence": evidence_rows[:12],
                    "status": "CANDIDATE",
                    "host_hints": list(record.get("host_hints") or [])[:8],
                }
            )
        candidate_rows.sort(key=lambda item: (float(item.get("confidence_score") or 0.0), len(item.get("source_types") or [])), reverse=True)

        if len(candidate_rows) > 1 and abs(float(candidate_rows[0].get("confidence_score") or 0.0) - float(candidate_rows[1].get("confidence_score") or 0.0)) <= 0.08:
            contradictions.append(
                {
                    "candidate_ips": [candidate_rows[0].get("candidate_ip"), candidate_rows[1].get("candidate_ip")],
                    "explanation": "Two materially competing IP candidates remained after correlation.",
                }
            )
            for candidate in candidate_rows[:2]:
                candidate["confidence_score"] = round(max(0.0, float(candidate.get("confidence_score") or 0.0) - 0.12), 2)
                candidate["confidence"] = self._confidence_label(float(candidate.get("confidence_score") or 0.0))

        validated_candidates: List[Dict[str, Any]] = []
        rejected_candidates: List[Dict[str, Any]] = []
        for candidate in candidate_rows:
            sources = set(candidate.get("source_types") or [])
            score = float(candidate.get("confidence_score") or 0.0)
            validated = (
                "DHCP_ACK" in sources
                or "ARP_SENDER" in sources
                or ("NEIGHBOR_TABLE" in sources and score >= 0.75)
                or (len(sources.intersection({"IP_SRC", "DHCP_EVIDENCE", "ARP_TARGET", "NEIGHBOR_TABLE"})) >= 2 and score >= 0.8)
            )
            if not validated and self._looks_private(str(candidate.get("candidate_ip") or "")):
                safe_validation = self._safe_connect_validation(str(candidate.get("candidate_ip") or ""))
                if safe_validation.get("validated") and (
                    "ACTIVE_PROBE_HINT" in sources
                    or "TARGET_FIELD" in sources
                    or "STABLE_DHCP_HINT" in sources
                    or score >= 0.62
                ):
                    candidate["evidence"] = [
                        *list(candidate.get("evidence") or []),
                        {
                            "pcap_file": "",
                            "frame_number": 0,
                            "timestamp": "",
                            "method": str(safe_validation.get("method") or ""),
                            "explanation": str(safe_validation.get("explanation") or ""),
                        },
                    ]
                    candidate["confidence_score"] = round(min(0.99, score + 0.24), 2)
                    candidate["confidence"] = self._confidence_label(float(candidate.get("confidence_score") or 0.0))
                    sources.add("SAFE_CONNECT")
                    candidate["source_types"] = sorted(sources)
                    validated = True
            if contradictions and candidate in candidate_rows[:2] and score < 0.85:
                validated = False
            candidate["status"] = "VALIDATED" if validated else ("LOW_CONFIDENCE" if score < 0.65 else "CANDIDATE")
            if validated:
                validated_candidates.append(candidate)
            else:
                rejected_candidates.append(candidate)

        resolution_state = "CANDIDATES_FOUND"
        if validated_candidates:
            resolution_state = "VALIDATED_MULTI_IP" if len(validated_candidates) > 1 else "VALIDATED_IP"
        elif contradictions:
            resolution_state = "INCONCLUSIVE_CONFLICT"
        elif all(float(item.get("confidence_score") or 0.0) < 0.65 for item in candidate_rows):
            resolution_state = "LOW_CONFIDENCE_ONLY"
        elif candidate_rows:
            resolution_state = "CANDIDATES_FOUND"

        if validated_candidates:
            explanation = (
                f"Validated IP {validated_candidates[0].get('candidate_ip')} from "
                f"{', '.join(validated_candidates[0].get('source_types') or [])}."
            )
        elif contradictions:
            explanation = "Two contradictory candidates existed and neither met the validation threshold without unresolved conflict."
        elif resolution_state == "LOW_CONFIDENCE_ONLY":
            explanation = "No validated IP. Only low-confidence inference existed and no candidate met the validation threshold."
        else:
            explanation = "Candidates were found, but no candidate satisfied the deterministic validation policy."

        evidence_rows = []
        for candidate in validated_candidates or candidate_rows[:3]:
            for evidence in list(candidate.get("evidence") or [])[:4]:
                evidence_rows.append(evidence)
        all_timestamps = [item.get("timestamp") or "" for item in evidence_rows if item.get("timestamp")]
        return {
            "target_id": target_id,
            "mac": str(target.get("mac") or target.get("bssid") or "").strip().lower(),
            "associated_bssid": associated_bssid,
            "candidate_ips": candidate_rows,
            "validated_candidates": validated_candidates,
            "rejected_candidates": rejected_candidates,
            "contradictory_evidence": contradictions,
            "confidence_summary": {
                "highest_score": round(float(candidate_rows[0].get("confidence_score") or 0.0), 2),
                "highest_confidence": candidate_rows[0].get("confidence") or "UNSUPPORTED",
                "source_count": len(candidate_rows[0].get("source_types") or []),
            },
            "resolution_state": resolution_state,
            "explanation": explanation,
            "evidence": evidence_rows[:16],
            "negative_evidence": negative_evidence,
            "test_trace": test_trace,
            "first_seen": min(all_timestamps) if all_timestamps else "",
            "last_seen": max(all_timestamps) if all_timestamps else "",
            "host_hints": host_hints[:12],
        }
