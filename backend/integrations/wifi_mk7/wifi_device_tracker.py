from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from backend.intel.identity.mac_oui_resolver import MacOUIResolver
from backend.integrations.wifi_mk7.authentication_evidence_tracker import AuthenticationEvidenceTracker
from backend.integrations.wifi_mk7.passive_event_engine import PassiveEventEngine


class WiFiDeviceTracker:
    HISTORY_SAVE_INTERVAL_SEC = 8.0

    def __init__(self, history_path: Path | None = None) -> None:
        self.oui = MacOUIResolver()
        self.networks: Dict[str, Dict[str, Any]] = {}
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.recent_pcaps: List[Dict[str, Any]] = []
        self.timeline: List[Dict[str, Any]] = []
        self.channel_activity: Dict[int, Dict[str, Any]] = {}
        self.history_path = history_path
        self.history: Dict[str, Dict[str, Dict[str, Any]]] = {"networks": {}, "clients": {}}
        self._history_dirty = False
        self._last_history_save_at = 0.0
        self.auth_tracker = AuthenticationEvidenceTracker()
        self.event_engine = PassiveEventEngine()
        self._load_history()

    def reset(self) -> None:
        self.networks = {}
        self.clients = {}
        self.recent_pcaps = []
        self.timeline = []
        self.channel_activity = {}
        self.auth_tracker = AuthenticationEvidenceTracker()

    def _load_history(self) -> None:
        if not self.history_path or not self.history_path.exists():
            return
        try:
            loaded = json.loads(self.history_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.history["networks"] = dict(loaded.get("networks") or {})
                self.history["clients"] = dict(loaded.get("clients") or {})
        except Exception:
            self.history = {"networks": {}, "clients": {}}
        self._history_dirty = False

    def _save_history(self, *, force: bool = False) -> None:
        if not self.history_path:
            return
        if not self._history_dirty and not force:
            return
        now = time.time()
        if not force and (now - self._last_history_save_at) < self.HISTORY_SAVE_INTERVAL_SEC:
            return
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            self.history_path.write_text(json.dumps(self.history, indent=2, sort_keys=True), encoding="utf-8")
            self._history_dirty = False
            self._last_history_save_at = now
        except Exception:
            pass

    def flush_history(self, *, force: bool = False) -> None:
        self._save_history(force=force)

    def _vendor_profile(self, mac: str) -> Dict[str, Any]:
        return self.oui.resolve(mac)

    def _infer_device_type(self, vendor: str | None, ssids: List[str]) -> str:
        joined = " ".join(ssids).lower()
        vendor_text = str(vendor or "").lower()
        if any(token in joined for token in ("cam", "camera", "baby", "monitor")) or any(token in vendor_text for token in ("hikvision", "arlo", "reolink", "wyze", "ring")):
            return "camera"
        if any(token in joined for token in ("tv", "roku", "chromecast", "firetv")):
            return "media"
        if any(token in joined for token in ("plug", "bulb", "thermo", "sensor", "iot")):
            return "iot"
        return "client"

    def _band_for_channel(self, channel: int | None, fallback: str) -> str:
        if channel is None:
            return fallback
        return "2.4 GHz" if channel <= 14 else "5 GHz"

    def _network_key(self, bssid: str, ssid: str, channel: int | None, band: str) -> str:
        if bssid and bssid != "ff:ff:ff:ff:ff:ff":
            return bssid
        normalized_ssid = ssid or "<hidden>"
        return f"unresolved::{normalized_ssid.lower()}::{channel or 0}::{band.lower()}"

    @staticmethod
    def _is_broadcast(mac: str) -> bool:
        return mac in {"", "ff:ff:ff:ff:ff:ff"}

    @staticmethod
    def _is_group_address(mac: str) -> bool:
        raw = str(mac or "").strip().lower()
        if not raw:
            return True
        if raw.startswith(("33:33:", "01:00:5e:", "01:80:c2:")):
            return True
        try:
            first_octet = int(raw.split(":", 1)[0], 16)
            return bool(first_octet & 0x01)
        except Exception:
            return False

    @staticmethod
    def _frame_type_label(frame_type: int | None) -> str:
        if frame_type == 0:
            return "management"
        if frame_type == 1:
            return "control"
        if frame_type == 2:
            return "data"
        return "other"

    def _resolve_client_mac(self, frame: Dict[str, Any], bssid: str) -> str:
        subtype = str(frame.get("subtype_label") or "")
        frame_type = int(frame.get("frame_type") or -1)
        source = str(frame.get("source") or frame.get("transmitter") or "").lower()
        transmitter = str(frame.get("transmitter") or "").lower()
        destination = str(frame.get("destination") or "").lower()
        receiver = str(frame.get("receiver") or "").lower()
        if subtype in {"probe_request", "association_request", "authentication"} and source and source != bssid:
            return source
        if frame_type == 2 and bssid:
            if source and source != bssid and (destination == bssid or receiver == bssid):
                return source
            if source == bssid or transmitter == bssid:
                for candidate in (destination, receiver):
                    if candidate and candidate != bssid and not self._is_broadcast(candidate) and not self._is_group_address(candidate):
                        return candidate
        return ""

    @staticmethod
    def _update_rssi_stats(record: Dict[str, Any], rssi: float | None) -> None:
        if rssi is None:
            return
        samples = list(record.get("rssi_samples") or [])
        samples.append(float(rssi))
        samples = samples[-8:]
        record["rssi_samples"] = samples
        record["rssi_min_dbm"] = min(samples)
        record["rssi_max_dbm"] = max(samples)
        record["rssi_variance_db"] = round(max(samples) - min(samples), 1) if len(samples) > 1 else 0.0

    @staticmethod
    def _update_activity(record: Dict[str, Any], now: float, packet_increment: int = 1) -> None:
        packet_times = list(record.get("packet_timestamps") or [])
        for _ in range(packet_increment):
            packet_times.append(now)
        packet_times = packet_times[-20:]
        record["packet_timestamps"] = packet_times
        if len(packet_times) >= 2:
            deltas = [packet_times[index] - packet_times[index - 1] for index in range(1, len(packet_times))]
            record["avg_interarrival_seconds"] = round(sum(deltas) / len(deltas), 3)
            record["activity_span_seconds"] = round(packet_times[-1] - packet_times[0], 3)
        else:
            record["avg_interarrival_seconds"] = 0.0
            record["activity_span_seconds"] = 0.0

    @staticmethod
    def _append_unique(record: Dict[str, Any], field: str, value: str, limit: int = 6) -> None:
        cleaned = str(value or "").strip()
        if not cleaned:
            return
        values = list(record.get(field) or [])
        if cleaned in values:
            return
        record[field] = [cleaned, *values][:limit]

    @staticmethod
    def _append_service_inventory(record: Dict[str, Any], entry: Dict[str, Any], limit: int = 12) -> None:
        if not isinstance(entry, dict):
            return
        service_name = str(entry.get("service_name") or "").strip().lower()
        port = int(entry.get("service_port") or 0)
        transport = str(entry.get("transport") or "").strip().lower()
        protocol_source = str(entry.get("protocol_source") or "").strip().lower()
        detail = str(entry.get("evidence_detail") or "").strip()
        if not any((service_name, port, detail)):
            return
        normalized = {
            "service_name": service_name,
            "service_port": port,
            "transport": transport,
            "protocol_source": protocol_source,
            "evidence_detail": detail,
        }
        inventory = list(record.get("service_inventory") or [])
        if normalized in inventory:
            return
        record["service_inventory"] = [normalized, *inventory][:limit]

    @staticmethod
    def _append_profile_count(record: Dict[str, Any], field: str, value: str, limit: int = 16) -> None:
        cleaned = str(value or "").strip().lower()
        if not cleaned:
            return
        counts = Counter(record.get(field) or {})
        counts[cleaned] += 1
        record[field] = dict(counts.most_common(limit))

    @staticmethod
    def _record_evidence(
        record: Dict[str, Any],
        *,
        evidence_type: str,
        value: str,
        protocol: str,
        direction: str,
        source: str,
        pcap_path: str,
        exact_field: str = "",
        related_ip: str = "",
        related_domain: str = "",
        limit: int = 40,
    ) -> None:
        normalized_value = str(value or "").strip()
        if not normalized_value:
            return
        evidence = list(record.get("evidence_provenance") or [])
        signature = {
            "type": evidence_type,
            "value": normalized_value,
            "protocol": str(protocol or "").strip().lower(),
            "direction": str(direction or "").strip().lower(),
            "source": str(source or "").strip().lower(),
            "pcap_path": str(pcap_path or "").strip(),
            "exact_field": str(exact_field or "").strip(),
            "related_ip": str(related_ip or "").strip(),
            "related_domain": str(related_domain or "").strip().lower(),
        }
        now = time.time()
        for entry in evidence:
            if all(entry.get(key) == signature.get(key) for key in signature):
                entry["count"] = int(entry.get("count") or 0) + 1
                entry["last_seen"] = now
                record["evidence_provenance"] = evidence[:limit]
                return
        record["evidence_provenance"] = [
            {
                **signature,
                "first_seen": now,
                "last_seen": now,
                "count": 1,
            },
            *evidence,
        ][:limit]

    def _update_history_profile(self, group: str, key: str, field: str, value: str, now: float | None = None) -> None:
        if not key:
            return
        normalized = str(value or "").strip().lower()
        if not normalized:
            return
        bucket = self.history.setdefault(group, {}).setdefault(
            key,
            {
                "captures": 0,
                "days_seen": 0,
                "last_day": "",
                "first_seen": now or time.time(),
                "last_seen": now or time.time(),
                "last_device_type": "",
            },
        )
        profile = dict(bucket.get(field) or {})
        profile[normalized] = int(profile.get(normalized) or 0) + 1
        bucket[field] = dict(Counter(profile).most_common(24))
        self._history_dirty = True

    def _apply_history_profiles(self, group: str, key: str, record: Dict[str, Any]) -> None:
        bucket = (self.history.get(group) or {}).get(key) or {}
        record["recurring_domain_profiles"] = dict(bucket.get("recurring_domains") or {})
        record["recurring_destination_profiles"] = dict(bucket.get("recurring_destination_ips") or {})
        record["recurring_service_profiles"] = dict(bucket.get("recurring_services") or {})
        record["recurring_tls_fingerprints"] = dict(bucket.get("recurring_tls_fingerprints") or {})
        record["dhcp_fingerprint_buckets"] = dict(bucket.get("dhcp_fingerprint_buckets") or {})

    def _propagate_client_evidence_to_network(
        self,
        client: Dict[str, Any],
        evidence_type: str,
        value: str,
        protocol: str,
        direction: str,
        source: str,
        pcap_path: str,
        exact_field: str = "",
        related_ip: str = "",
        related_domain: str = "",
    ) -> None:
        associated_bssid = str(client.get("associated_bssid") or "").lower()
        if not associated_bssid:
            return
        for record_key, network in self.networks.items():
            if str(network.get("bssid") or "").lower() != associated_bssid:
                continue
            self._record_evidence(
                network,
                evidence_type=evidence_type,
                value=value,
                protocol=protocol,
                direction=direction,
                source=source,
                pcap_path=pcap_path,
                exact_field=exact_field,
                related_ip=related_ip,
                related_domain=related_domain,
            )
            if protocol in {"dns", "mdns"} and related_domain:
                self._append_profile_count(network, "resolved_domain_counts", related_domain)
            if related_ip:
                self._append_profile_count(network, "destination_ip_counts", related_ip)
            if protocol in {"rtsp", "http", "tls", "quic", "mdns"}:
                self._append_profile_count(network, "service_name_counts", evidence_type)
            self._update_history_profile("networks", record_key, "recurring_domains", related_domain)
            self._update_history_profile("networks", record_key, "recurring_destination_ips", related_ip)
            self._update_history_profile("networks", record_key, "recurring_services", evidence_type)
            if evidence_type in {"tls_ja3", "tls_ja3s", "tls_ja4"}:
                self._update_history_profile("networks", record_key, "recurring_tls_fingerprints", value)
            if evidence_type in {"dhcp_vendor_class_id", "dhcp_parameter_request_list"}:
                self._update_history_profile("networks", record_key, "dhcp_fingerprint_buckets", value)
            self._append_unique(network, "enrichment_sources", source, limit=8)
            network["identity_enriched"] = True
            network["last_enriched_at"] = time.time()
            self._apply_history_profiles("networks", record_key, network)
            break

    @staticmethod
    def _update_frame_metrics(record: Dict[str, Any], frame: Dict[str, Any]) -> None:
        frame_len = int(frame.get("frame_len") or 0)
        frame_type = int(frame.get("frame_type") or -1)
        retry = bool(frame.get("retry"))
        qos_priority = frame.get("qos_priority")
        eapol_type = frame.get("eapol_type")
        hostname = str(frame.get("dhcp_hostname") or "").strip()
        data_rate = frame.get("data_rate_mbps")

        record["frame_count_total"] = int(record.get("frame_count_total") or 0) + 1
        record["retry_count"] = int(record.get("retry_count") or 0) + (1 if retry else 0)
        record["eapol_count"] = int(record.get("eapol_count") or 0) + (1 if eapol_type else 0)
        record["qos_frame_count"] = int(record.get("qos_frame_count") or 0) + (1 if qos_priority is not None else 0)
        record["frame_bytes_total"] = int(record.get("frame_bytes_total") or 0) + max(0, frame_len)
        record["max_frame_len"] = max(int(record.get("max_frame_len") or 0), frame_len)
        count = max(1, int(record.get("frame_count_total") or 1))
        record["avg_frame_len"] = round(float(record.get("frame_bytes_total") or 0) / float(count), 1)
        if data_rate is not None:
            record["last_data_rate_mbps"] = data_rate
        if hostname:
            WiFiDeviceTracker._append_unique(record, "dhcp_hostnames", hostname, limit=4)
        if frame.get("ht_capabilities"):
            record["ht_capable"] = True
        if frame.get("vht_capabilities"):
            record["vht_capable"] = True
        if frame.get("he_capable"):
            record["he_capable"] = True
        if frame.get("wps_primary_device_camera"):
            record["wps_primary_device_camera"] = True
        frame_type_counts = dict(record.get("frame_type_counts") or {})
        label = WiFiDeviceTracker._frame_type_label(frame_type)
        frame_type_counts[label] = int(frame_type_counts.get(label) or 0) + 1
        record["frame_type_counts"] = frame_type_counts
        subtype = str(frame.get("subtype_label") or "")
        if subtype == "association_request":
            record["association_event_count"] = int(record.get("association_event_count") or 0) + 1
        elif subtype == "reassociation_request":
            record["reassociation_event_count"] = int(record.get("reassociation_event_count") or 0) + 1
        elif subtype == "authentication":
            record["authentication_event_count"] = int(record.get("authentication_event_count") or 0) + 1

    @staticmethod
    def _update_flow_metrics(record: Dict[str, Any], frame: Dict[str, Any], subject_mac: str, peer_mac: str) -> None:
        if int(frame.get("frame_type") or -1) != 2:
            return
        source = str(frame.get("source") or frame.get("transmitter") or "").lower()
        destination = str(frame.get("destination") or frame.get("receiver") or "").lower()
        subject = str(subject_mac or "").lower()
        peer = str(peer_mac or "").lower()
        if not subject:
            return
        frame_len = max(0, int(frame.get("frame_len") or 0))
        flow = dict(record.get("flow_metrics") or {})
        flow.setdefault("uplink_packets", 0)
        flow.setdefault("downlink_packets", 0)
        flow.setdefault("uplink_bytes", 0)
        flow.setdefault("downlink_bytes", 0)
        flow.setdefault("last_direction", "")

        if source == subject and (not peer or destination == peer):
            flow["uplink_packets"] = int(flow.get("uplink_packets") or 0) + 1
            flow["uplink_bytes"] = int(flow.get("uplink_bytes") or 0) + frame_len
            flow["last_direction"] = "uplink"
        elif destination == subject and (not peer or source == peer):
            flow["downlink_packets"] = int(flow.get("downlink_packets") or 0) + 1
            flow["downlink_bytes"] = int(flow.get("downlink_bytes") or 0) + frame_len
            flow["last_direction"] = "downlink"

        record["flow_metrics"] = flow

    @staticmethod
    def _finalize_flow_metrics(record: Dict[str, Any]) -> None:
        flow = dict(record.get("flow_metrics") or {})
        up_packets = int(flow.get("uplink_packets") or 0)
        down_packets = int(flow.get("downlink_packets") or 0)
        up_bytes = int(flow.get("uplink_bytes") or 0)
        down_bytes = int(flow.get("downlink_bytes") or 0)
        total_packets = up_packets + down_packets
        total_bytes = up_bytes + down_bytes
        duration = float(record.get("activity_span_seconds") or 0.0)

        flow["total_packets"] = total_packets
        flow["total_bytes"] = total_bytes
        flow["duration_seconds"] = round(duration, 3)
        flow["uplink_ratio"] = round((up_bytes / total_bytes), 3) if total_bytes > 0 else 0.0
        flow["packet_rate_pps"] = round((total_packets / duration), 3) if duration > 0 else float(total_packets)
        avg_frame_len = float(record.get("avg_frame_len") or 0.0)
        max_frame_len = float(record.get("max_frame_len") or 0.0)
        flow["bitrate_variance"] = round(abs(max_frame_len - avg_frame_len) / max(max_frame_len, 1.0), 3) if max_frame_len > 0 else 1.0
        has_real_flow = total_packets >= 8 and total_bytes >= 1200
        flow["constant_bitrate"] = bool(has_real_flow and duration >= 30.0 and total_packets >= 12 and flow["bitrate_variance"] <= 0.35)
        flow["long_lived_flow"] = bool(has_real_flow and duration >= 30.0)
        record["flow_metrics"] = flow

    @staticmethod
    def _mobility_class(rssi_variance_db: float | None) -> str:
        variance = float(rssi_variance_db or 0.0)
        if variance >= 18:
            return "high-mobility"
        if variance >= 8:
            return "low-mobility"
        return "static"

    @staticmethod
    def _traffic_pattern(record: Dict[str, Any]) -> str:
        packet_count = int(record.get("packet_count") or 0)
        probe_count = int(record.get("probe_request_count") or 0)
        beacon_count = int(record.get("beacon_count") or 0)
        data_frame_count = int((record.get("frame_type_counts") or {}).get("data") or 0)
        avg_gap = float(record.get("avg_interarrival_seconds") or 0.0)
        if beacon_count >= 12:
            return "broadcast-heavy"
        if data_frame_count >= 12 and packet_count >= 20 and probe_count == 0 and (avg_gap == 0.0 or avg_gap <= 1.2):
            return "steady-stream"
        if probe_count >= 3:
            return "probe-bursty"
        if packet_count >= 3 and avg_gap >= 3.0:
            return "periodic"
        return "mixed"

    def _touch_history(self, group: str, key: str, now: float, record: Dict[str, Any]) -> None:
        if not key:
            return
        bucket = self.history.setdefault(group, {}).setdefault(
            key,
            {
                "captures": 0,
                "days_seen": 0,
                "last_day": "",
                "first_seen": now,
                "last_seen": now,
                "last_device_type": "",
            },
        )
        bucket["captures"] = int(bucket.get("captures") or 0) + 1
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        if bucket.get("last_day") != day:
            bucket["days_seen"] = int(bucket.get("days_seen") or 0) + 1
            bucket["last_day"] = day
        bucket["last_seen"] = now
        bucket["first_seen"] = min(float(bucket.get("first_seen") or now), now)
        bucket["last_device_type"] = str(record.get("device_type") or record.get("ssid") or "")
        self._history_dirty = True

    @staticmethod
    def _handshake_status(eapol_count: int) -> str:
        return "Captured" if int(eapol_count or 0) > 0 else "Not Captured"

    @staticmethod
    def _touch_handshake(record: Dict[str, Any], now: float, related_mac: str = "") -> None:
        if not record.get("handshake_first_seen"):
            record["handshake_first_seen"] = now
        record["handshake_last_seen"] = now
        record["handshake_captured"] = True
        record["handshake_status"] = "Captured"
        if related_mac:
            WiFiDeviceTracker._append_unique(record, "handshake_related_macs", related_mac, limit=8)

    def _apply_history(self, group: str, key: str, record: Dict[str, Any]) -> None:
        bucket = (self.history.get(group) or {}).get(key) or {}
        record["historical_captures"] = int(bucket.get("captures") or 0)
        record["historical_days_seen"] = int(bucket.get("days_seen") or 0)
        record["historical_first_seen"] = bucket.get("first_seen")
        record["historical_last_seen"] = bucket.get("last_seen")
        identity_hints: List[str] = []
        current_hint = str(bucket.get("last_device_type") or "").strip()
        if current_hint and current_hint.lower() not in {"client", "<hidden>", "unknown"}:
            identity_hints.append(current_hint)
        if group == "clients":
            related_network_bucket = (self.history.get("networks") or {}).get(key) or {}
            related_hint = str(related_network_bucket.get("last_device_type") or "").strip()
            if related_hint and related_hint.lower() not in {"client", "<hidden>", "unknown"} and related_hint not in identity_hints:
                identity_hints.append(related_hint)
        elif group == "networks":
            related_client_bucket = (self.history.get("clients") or {}).get(key) or {}
            related_hint = str(related_client_bucket.get("last_device_type") or "").strip()
            if related_hint and related_hint.lower() not in {"client", "<hidden>", "unknown"} and related_hint not in identity_hints:
                identity_hints.append(related_hint)
        record["historical_identity_hint"] = identity_hints[0] if identity_hints else ""
        record["related_identity_hints"] = identity_hints[:4]
        self._apply_history_profiles(group, key, record)

    def ingest_capture(self, channel: int, band: str, pcap_path: str, frames: List[Dict[str, Any]]) -> None:
        now = time.time()
        self.auth_tracker.process_frames(frames, pcap_path=pcap_path)
        event_summary = self.event_engine.summarize_channel_events(frames)
        activity = self.channel_activity.setdefault(
            int(channel),
            {
                "captures": 0,
                "frames": 0,
                "eapol_frames": 0,
                "association_events": 0,
                "reassociation_events": 0,
                "authentication_events": 0,
                "probe_requests": 0,
                "auth_activity": 0,
                "last_seen": None,
            },
        )
        activity["captures"] = int(activity.get("captures") or 0) + 1
        activity["frames"] = int(activity.get("frames") or 0) + len(frames)
        activity["eapol_frames"] = int(activity.get("eapol_frames") or 0) + int(event_summary.get("eapol_frames") or 0)
        activity["association_events"] = int(activity.get("association_events") or 0) + int(event_summary.get("association_events") or 0)
        activity["reassociation_events"] = int(activity.get("reassociation_events") or 0) + int(event_summary.get("reassociation_events") or 0)
        activity["authentication_events"] = int(activity.get("authentication_events") or 0) + int(event_summary.get("authentication_events") or 0)
        activity["probe_requests"] = int(activity.get("probe_requests") or 0) + int(event_summary.get("probe_requests") or 0)
        activity["auth_activity"] = int(activity.get("auth_activity") or 0) + int(event_summary.get("auth_activity") or 0)
        activity["last_seen"] = now
        self.recent_pcaps.insert(0, {"path": pcap_path, "channel": channel, "band": band, "captured_at": now, "frame_count": len(frames)})
        self.recent_pcaps = self.recent_pcaps[:20]
        touched_networks: set[str] = set()
        touched_clients: set[str] = set()

        for frame in frames:
            bssid = str(frame.get("bssid") or "").lower()
            ssid = str(frame.get("ssid") or "").strip()
            subtype = str(frame.get("subtype_label") or "")
            rssi = frame.get("rssi_dbm")
            eapol_type = frame.get("eapol_type")
            effective_channel = frame.get("channel") or channel
            effective_band = self._band_for_channel(effective_channel, band)
            record_key = self._network_key(bssid, ssid, effective_channel, effective_band)

            if (bssid and bssid != "ff:ff:ff:ff:ff:ff") or ssid:
                bssid_vendor = self._vendor_profile(bssid)
                network = self.networks.setdefault(
                    record_key,
                    {
                        "record_id": record_key,
                        "bssid": bssid,
                        "ssid": ssid or "<hidden>",
                        "hidden_ssid": not bool(ssid),
                        "channel": effective_channel,
                        "band": effective_band,
                        "security": frame.get("security") or "Unknown",
                        "akm": frame.get("akm") or "",
                        "cipher": frame.get("cipher") or "",
                        "pmf": frame.get("pmf") or "",
                        "rssi_dbm": rssi,
                        "vendor": bssid_vendor.get("vendor"),
                        "vendor_country": bssid_vendor.get("country"),
                        "vendor_country_code": bssid_vendor.get("country_code"),
                        "vendor_country_source": bssid_vendor.get("country_source"),
                        "evidence_tier": "Confirmed" if bssid and bssid != "ff:ff:ff:ff:ff:ff" else "Probable",
                        "evidence_reason": "BSSID observed in frame" if bssid and bssid != "ff:ff:ff:ff:ff:ff" else "SSID observed without stable BSSID",
                        "synthetic_identity": not bool(bssid and bssid != "ff:ff:ff:ff:ff:ff"),
                        "packet_count": 0,
                        "observation_capture_count": 0,
                        "beacon_count": 0,
                        "probe_response_count": 0,
                        "client_count": 0,
                        "wps_manufacturer": frame.get("wps_manufacturer") or "",
                        "wps_model_name": frame.get("wps_model_name") or "",
                        "wps_device_name": frame.get("wps_device_name") or "",
                        "wps_model_number": frame.get("wps_model_number") or "",
                        "wps_serial_number": frame.get("wps_serial_number") or "",
                        "wps_config_methods": frame.get("wps_config_methods") or "",
                        "wps_rf_bands": frame.get("wps_rf_bands") or "",
                        "wps_primary_device_camera": bool(frame.get("wps_primary_device_camera")),
                        "supported_rates": frame.get("supported_rates") or "",
                        "extended_supported_rates": frame.get("extended_supported_rates") or "",
                        "dhcp_hostnames": [],
                        "frame_type_counts": {},
                        "frame_count_total": 0,
                        "frame_bytes_total": 0,
                        "avg_frame_len": 0.0,
                        "max_frame_len": 0,
                        "retry_count": 0,
                        "eapol_count": 0,
                        "handshake_captured": False,
                        "handshake_status": "Not Captured",
                        "handshake_first_seen": None,
                        "handshake_last_seen": None,
                        "handshake_related_macs": [],
                        "qos_frame_count": 0,
                        "last_data_rate_mbps": None,
                        "ht_capable": False,
                        "vht_capable": False,
                        "he_capable": False,
                        "rssi_samples": [],
                        "rssi_min_dbm": rssi,
                        "rssi_max_dbm": rssi,
                        "rssi_variance_db": 0.0,
                        "packet_timestamps": [],
                        "avg_interarrival_seconds": 0.0,
                        "activity_span_seconds": 0.0,
                        "flow_metrics": {},
                        "association_event_count": 0,
                        "reassociation_event_count": 0,
                        "authentication_event_count": 0,
                        "auth_event_count": 0,
                        "probe_burst_count": 0,
                        "mobility_event_count": 0,
                        "first_seen": now,
                        "last_seen": now,
                    },
                )
                network["packet_count"] += 1
                network["last_seen"] = now
                network["channel"] = effective_channel
                network["band"] = effective_band
                if ssid:
                    network["ssid"] = ssid
                    network["hidden_ssid"] = False
                if rssi is not None:
                    network["rssi_dbm"] = rssi
                if frame.get("security"):
                    network["security"] = frame["security"]
                if frame.get("akm"):
                    network["akm"] = frame["akm"]
                if frame.get("cipher"):
                    network["cipher"] = frame["cipher"]
                if frame.get("wps_manufacturer"):
                    network["wps_manufacturer"] = frame["wps_manufacturer"]
                if frame.get("wps_model_name"):
                    network["wps_model_name"] = frame["wps_model_name"]
                if frame.get("wps_device_name"):
                    network["wps_device_name"] = frame["wps_device_name"]
                if frame.get("wps_model_number"):
                    network["wps_model_number"] = frame["wps_model_number"]
                if frame.get("wps_serial_number"):
                    network["wps_serial_number"] = frame["wps_serial_number"]
                if frame.get("wps_config_methods"):
                    network["wps_config_methods"] = frame["wps_config_methods"]
                if frame.get("wps_rf_bands"):
                    network["wps_rf_bands"] = frame["wps_rf_bands"]
                if frame.get("wps_primary_device_camera"):
                    network["wps_primary_device_camera"] = True
                if frame.get("supported_rates"):
                    network["supported_rates"] = frame["supported_rates"]
                if frame.get("extended_supported_rates"):
                    network["extended_supported_rates"] = frame["extended_supported_rates"]
                self._update_rssi_stats(network, rssi)
                self._update_activity(network, now)
                self._update_frame_metrics(network, frame)
                self._update_flow_metrics(network, frame, bssid, "")
                if eapol_type:
                    self._touch_handshake(network, now)
                if bssid and bssid != "ff:ff:ff:ff:ff:ff":
                    network["bssid"] = bssid
                    network["evidence_tier"] = "Confirmed"
                    network["evidence_reason"] = "BSSID observed in frame"
                    network["synthetic_identity"] = False
                if subtype == "beacon":
                    network["beacon_count"] += 1
                elif subtype == "probe_response":
                    network["probe_response_count"] += 1
                touched_networks.add(record_key)

            client_mac = self._resolve_client_mac(frame, bssid)
            if client_mac:
                source_vendor = self._vendor_profile(client_mac)
                client = self.clients.setdefault(
                    client_mac,
                    {
                        "mac": client_mac,
                        "vendor": source_vendor.get("vendor"),
                        "vendor_country": source_vendor.get("country"),
                        "vendor_country_code": source_vendor.get("country_code"),
                        "vendor_country_source": source_vendor.get("country_source"),
                        "associated_bssid": bssid if (bssid and not self._is_broadcast(bssid) and not self._is_group_address(bssid)) else "",
                        "last_ssids": [],
                        "packet_count": 0,
                        "probe_request_count": 0,
                        "association_count": 0,
                        "rssi_dbm": rssi,
                        "channel": effective_channel,
                        "band": effective_band,
                        "wps_manufacturer": frame.get("wps_manufacturer") or "",
                        "wps_model_name": frame.get("wps_model_name") or "",
                        "wps_device_name": frame.get("wps_device_name") or "",
                        "wps_model_number": frame.get("wps_model_number") or "",
                        "wps_serial_number": frame.get("wps_serial_number") or "",
                        "wps_config_methods": frame.get("wps_config_methods") or "",
                        "wps_rf_bands": frame.get("wps_rf_bands") or "",
                        "wps_primary_device_camera": bool(frame.get("wps_primary_device_camera")),
                        "supported_rates": frame.get("supported_rates") or "",
                        "extended_supported_rates": frame.get("extended_supported_rates") or "",
                        "dhcp_hostnames": [],
                        "frame_type_counts": {},
                        "frame_count_total": 0,
                        "frame_bytes_total": 0,
                        "avg_frame_len": 0.0,
                        "max_frame_len": 0,
                        "retry_count": 0,
                        "eapol_count": 0,
                        "handshake_captured": False,
                        "handshake_status": "Not Captured",
                        "handshake_first_seen": None,
                        "handshake_last_seen": None,
                        "handshake_related_macs": [],
                        "qos_frame_count": 0,
                        "last_data_rate_mbps": None,
                        "ht_capable": False,
                        "vht_capable": False,
                        "he_capable": False,
                        "associated_bssids": [],
                        "rssi_samples": [],
                        "rssi_min_dbm": rssi,
                        "rssi_max_dbm": rssi,
                        "rssi_variance_db": 0.0,
                        "packet_timestamps": [],
                        "avg_interarrival_seconds": 0.0,
                        "activity_span_seconds": 0.0,
                        "flow_metrics": {},
                        "association_event_count": 0,
                        "reassociation_event_count": 0,
                        "authentication_event_count": 0,
                        "auth_event_count": 0,
                        "probe_burst_count": 0,
                        "mobility_event_count": 0,
                        "first_seen": now,
                        "last_seen": now,
                        "device_type": "client",
                    },
                )
                client["packet_count"] += 1
                client["last_seen"] = now
                client["channel"] = effective_channel
                client["band"] = effective_band
                if rssi is not None:
                    client["rssi_dbm"] = rssi
                if bssid and not self._is_broadcast(bssid) and not self._is_group_address(bssid):
                    client["associated_bssid"] = bssid
                    self._append_unique(client, "associated_bssids", bssid, limit=6)
                if ssid and ssid not in client["last_ssids"]:
                    client["last_ssids"] = [ssid, *client["last_ssids"]][:5]
                if frame.get("wps_manufacturer"):
                    client["wps_manufacturer"] = frame["wps_manufacturer"]
                if frame.get("wps_model_name"):
                    client["wps_model_name"] = frame["wps_model_name"]
                if frame.get("wps_device_name"):
                    client["wps_device_name"] = frame["wps_device_name"]
                if frame.get("wps_model_number"):
                    client["wps_model_number"] = frame["wps_model_number"]
                if frame.get("wps_serial_number"):
                    client["wps_serial_number"] = frame["wps_serial_number"]
                if frame.get("wps_config_methods"):
                    client["wps_config_methods"] = frame["wps_config_methods"]
                if frame.get("wps_rf_bands"):
                    client["wps_rf_bands"] = frame["wps_rf_bands"]
                if frame.get("wps_primary_device_camera"):
                    client["wps_primary_device_camera"] = True
                if frame.get("supported_rates"):
                    client["supported_rates"] = frame["supported_rates"]
                if frame.get("extended_supported_rates"):
                    client["extended_supported_rates"] = frame["extended_supported_rates"]
                if subtype == "probe_request":
                    client["probe_request_count"] += 1
                if subtype in {"association_request", "association_response", "authentication"}:
                    client["association_count"] += 1
                self._update_rssi_stats(client, rssi)
                self._update_activity(client, now)
                self._update_frame_metrics(client, frame)
                self._update_flow_metrics(client, frame, client_mac, bssid)
                if eapol_type:
                    self._touch_handshake(client, now, bssid)
                client["device_type"] = self._infer_device_type(client.get("vendor"), client.get("last_ssids", []))
                touched_clients.add(client_mac)

        client_counts: Dict[str, int] = {}
        client_handshake_counts: Dict[str, int] = {}
        for client in self.clients.values():
            bssid = str(client.get("associated_bssid") or "")
            if bssid and not self._is_broadcast(bssid):
                client_counts[bssid] = client_counts.get(bssid, 0) + 1
                client_handshake_counts[bssid] = client_handshake_counts.get(bssid, 0) + int(client.get("eapol_count") or 0)
        for record_key in touched_networks:
            network = self.networks.get(record_key)
            if network:
                network["observation_capture_count"] = int(network.get("observation_capture_count") or 0) + 1
                self._touch_history("networks", record_key, now, network)
        for client_mac in touched_clients:
            client = self.clients.get(client_mac)
            if client:
                self._touch_history("clients", client_mac, now, client)
        auth_summary = self.auth_tracker.summary()
        session_quality_rank = {"NONE": 0, "PARTIAL": 1, "LIKELY": 2, "CONFIRMED": 3}
        network_session_counts: Dict[str, int] = {}
        network_session_frames: Dict[str, int] = {}
        network_session_quality: Dict[str, str] = {}
        client_session_counts: Dict[str, int] = {}
        client_session_frames: Dict[str, int] = {}
        client_session_quality: Dict[str, str] = {}
        for session in auth_summary.get("sessions") or []:
            bssid = str(session.get("bssid") or "")
            client_mac = str(session.get("client_mac") or "")
            quality = str(session.get("quality") or "NONE")
            frame_count = int(session.get("frame_count") or 0)
            if bssid:
                network_session_counts[bssid] = network_session_counts.get(bssid, 0) + 1
                network_session_frames[bssid] = network_session_frames.get(bssid, 0) + frame_count
                if session_quality_rank.get(quality, 0) >= session_quality_rank.get(network_session_quality.get(bssid, "NONE"), 0):
                    network_session_quality[bssid] = quality
            if client_mac:
                client_session_counts[client_mac] = client_session_counts.get(client_mac, 0) + 1
                client_session_frames[client_mac] = client_session_frames.get(client_mac, 0) + frame_count
                if session_quality_rank.get(quality, 0) >= session_quality_rank.get(client_session_quality.get(client_mac, "NONE"), 0):
                    client_session_quality[client_mac] = quality
        for record_key, network in self.networks.items():
            network_bssid = str(network.get("bssid") or "")
            if network_bssid and not self._is_broadcast(network_bssid):
                network["client_count"] = client_counts.get(network_bssid, 0)
            else:
                network["client_count"] = 0
            network_eapol_total = int(network.get("eapol_count") or 0) + int(client_handshake_counts.get(network_bssid, 0))
            network["handshake_eapol_count"] = network_eapol_total
            network["handshake_captured"] = network_eapol_total > 0
            network["handshake_status"] = self._handshake_status(network_eapol_total)
            network["authentication_evidence_session_count"] = int(network_session_counts.get(network_bssid, 0))
            network["authentication_evidence_frame_count"] = int(network_session_frames.get(network_bssid, 0))
            network["authentication_evidence_quality"] = str(network_session_quality.get(network_bssid, "NONE"))
            network["auth_event_count"] = (
                int(network.get("association_event_count") or 0)
                + int(network.get("reassociation_event_count") or 0)
                + int(network.get("authentication_event_count") or 0)
                + network_eapol_total
            )
            if network["handshake_captured"] and not network.get("handshake_first_seen"):
                network["handshake_first_seen"] = network.get("first_seen")
                network["handshake_last_seen"] = network.get("last_seen")
            network["mobility_class"] = self._mobility_class(network.get("rssi_variance_db"))
            network["traffic_pattern"] = self._traffic_pattern(network)
            network["mobility_event_count"] = 1 if str(network.get("mobility_class")) in {"high-mobility", "low-mobility"} else 0
            network["probe_burst_count"] = 1 if str(network.get("traffic_pattern")) == "probe-bursty" and int(network.get("probe_request_count") or 0) >= 3 else 0
            self._finalize_flow_metrics(network)
            self._apply_history("networks", record_key, network)
        for client in self.clients.values():
            client["handshake_captured"] = int(client.get("eapol_count") or 0) > 0
            client["handshake_status"] = self._handshake_status(client.get("eapol_count") or 0)
            client_mac = str(client.get("mac") or "")
            client["authentication_evidence_session_count"] = int(client_session_counts.get(client_mac, 0))
            client["authentication_evidence_frame_count"] = int(client_session_frames.get(client_mac, 0))
            client["authentication_evidence_quality"] = str(client_session_quality.get(client_mac, "NONE"))
            client["auth_event_count"] = (
                int(client.get("association_event_count") or 0)
                + int(client.get("reassociation_event_count") or 0)
                + int(client.get("authentication_event_count") or 0)
                + int(client.get("eapol_count") or 0)
            )
            if client["handshake_captured"] and not client.get("handshake_first_seen"):
                client["handshake_first_seen"] = client.get("first_seen")
                client["handshake_last_seen"] = client.get("last_seen")
            client["mobility_class"] = self._mobility_class(client.get("rssi_variance_db"))
            client["traffic_pattern"] = self._traffic_pattern(client)
            client["mobility_event_count"] = 1 if str(client.get("mobility_class")) in {"high-mobility", "low-mobility"} else 0
            client["probe_burst_count"] = 1 if str(client.get("traffic_pattern")) == "probe-bursty" and int(client.get("probe_request_count") or 0) >= 3 else 0
            self._finalize_flow_metrics(client)
            self._apply_history("clients", str(client.get("mac") or ""), client)
        self._save_history()

        self.timeline.insert(
            0,
            {
                "timestamp": now,
                "channel": channel,
                "band": band,
                "frame_count": len(frames),
                "raw_eapol_frame_count": int(event_summary.get("eapol_frames") or 0),
                "association_event_count": int(event_summary.get("association_events") or 0),
                "reassociation_event_count": int(event_summary.get("reassociation_events") or 0),
                "authentication_event_count": int(event_summary.get("authentication_events") or 0),
                "probe_request_count": int(event_summary.get("probe_requests") or 0),
                "touched_network_count": len(touched_networks),
                "touched_client_count": len(touched_clients),
                "pcap_path": pcap_path,
            },
        )
        self.timeline = self.timeline[:50]

    def ingest_enrichment(
        self,
        identities: List[Dict[str, Any]],
        service_inventory: List[Dict[str, Any]] | None = None,
        protocol_summary: Dict[str, Any] | None = None,
        pcap_path: str = "",
    ) -> None:
        now = time.time()
        for identity in identities:
            source = str(identity.get("source") or "").lower()
            destination = str(identity.get("destination") or "").lower()
            evidence_pcap = str(identity.get("pcap_path") or pcap_path or "")
            hostname = str(identity.get("hostname") or "").strip()
            vendor_class_id = str(identity.get("dhcp_vendor_class_id") or "").strip()
            request_list = str(identity.get("dhcp_parameter_request_list") or "").strip()
            query_name = str(identity.get("query_name") or "").strip()
            response_name = str(identity.get("dns_response_name") or "").strip()
            ptr_name = str(identity.get("ptr_name") or "").strip()
            http_host = str(identity.get("http_host") or "").strip()
            http_uri = str(identity.get("http_uri") or "").strip()
            user_agent = str(identity.get("http_user_agent") or "").strip()
            http_server = str(identity.get("http_server") or "").strip()
            rtsp_request = str(identity.get("rtsp_request") or "").strip()
            rtsp_url = str(identity.get("rtsp_url") or "").strip()
            server_name = str(identity.get("tls_server_name") or "").strip()
            quic_server_name = str(identity.get("quic_server_name") or "").strip()
            http3_authority = str(identity.get("http3_authority") or "").strip()
            http3_server = str(identity.get("http3_server") or "").strip()
            tls_subject = str(identity.get("tls_certificate_subject") or "").strip()
            tls_issuer = str(identity.get("tls_certificate_issuer") or "").strip()
            tls_ja3 = str(identity.get("tls_ja3") or "").strip()
            tls_ja3s = str(identity.get("tls_ja3s") or "").strip()
            tls_ja4 = str(identity.get("tls_ja4") or "").strip()
            source_ip = str(identity.get("source_ip") or "").strip()
            destination_ip = str(identity.get("destination_ip") or "").strip()
            mdns_service_type = str(identity.get("mdns_service_type") or "").strip()
            mdns_service_instance = str(identity.get("mdns_service_instance") or "").strip()
            protocol_source = str(identity.get("protocol_source") or "").strip()
            tls_subject_alt_names = list(identity.get("tls_subject_alt_names") or [])
            resolved_domains = [str(value).strip().lower() for value in (identity.get("resolved_domains") or []) if str(value).strip()]

            source_client = self.clients.get(source)
            destination_client = self.clients.get(destination)

            def apply_client_value(
                client: Dict[str, Any] | None,
                field: str,
                value: str,
                *,
                evidence_type: str,
                protocol: str,
                direction: str,
                related_ip: str = "",
                related_domain: str = "",
                exact_field: str = "",
            ) -> None:
                if not client or not value:
                    return
                self._append_unique(client, field, value, limit=8)
                self._record_evidence(
                    client,
                    evidence_type=evidence_type,
                    value=value,
                    protocol=protocol,
                    direction=direction,
                    source=protocol_source,
                    pcap_path=evidence_pcap,
                    exact_field=exact_field,
                    related_ip=related_ip,
                    related_domain=related_domain,
                )
                client["enrichment_count"] = int(client.get("enrichment_count") or 0) + 1
                client["last_enriched_at"] = now
                client["identity_enriched"] = True
                self._append_unique(client, "enrichment_sources", protocol_source, limit=8)
                if related_ip:
                    self._append_profile_count(client, "destination_ip_counts", related_ip)
                    self._update_history_profile("clients", str(client.get("mac") or ""), "recurring_destination_ips", related_ip, now)
                if related_domain:
                    self._append_profile_count(client, "resolved_domain_counts", related_domain)
                    self._update_history_profile("clients", str(client.get("mac") or ""), "recurring_domains", related_domain, now)
                self._update_history_profile("clients", str(client.get("mac") or ""), "recurring_services", evidence_type, now)
                if evidence_type in {"tls_ja3", "tls_ja3s", "tls_ja4"}:
                    self._update_history_profile("clients", str(client.get("mac") or ""), "recurring_tls_fingerprints", value, now)
                if evidence_type in {"dhcp_vendor_class_id", "dhcp_parameter_request_list"}:
                    self._update_history_profile("clients", str(client.get("mac") or ""), "dhcp_fingerprint_buckets", value, now)
                self._apply_history_profiles("clients", str(client.get("mac") or ""), client)
                self._propagate_client_evidence_to_network(
                    client,
                    evidence_type=evidence_type,
                    value=value,
                    protocol=protocol,
                    direction=direction,
                    source=protocol_source,
                    pcap_path=evidence_pcap,
                    exact_field=exact_field,
                    related_ip=related_ip,
                    related_domain=related_domain,
                )

            apply_client_value(source_client, "dhcp_hostnames", hostname, evidence_type="dhcp_hostname", protocol="dhcp", direction="outbound", exact_field="dhcp.option.hostname")
            apply_client_value(source_client, "dhcp_vendor_class_ids", vendor_class_id, evidence_type="dhcp_vendor_class_id", protocol="dhcp", direction="outbound", exact_field="dhcp.option.vendor_class_id")
            apply_client_value(source_client, "dhcp_parameter_request_lists", request_list, evidence_type="dhcp_parameter_request_list", protocol="dhcp", direction="outbound", exact_field="dhcp.option.request_list_item")
            apply_client_value(source_client, "dns_query_names", query_name, evidence_type="dns_query", protocol="dns", direction="outbound", related_ip=destination_ip, related_domain=query_name.lower(), exact_field="dns.qry.name")
            apply_client_value(source_client, "http_hosts", http_host, evidence_type="http_host", protocol="http", direction="outbound", related_ip=destination_ip, related_domain=http_host.lower(), exact_field="http.host")
            apply_client_value(source_client, "http_uris", http_uri, evidence_type="http_uri", protocol="http", direction="outbound", related_ip=destination_ip, exact_field="http.request.full_uri")
            apply_client_value(source_client, "http_user_agents", user_agent, evidence_type="http_user_agent", protocol="http", direction="outbound", related_ip=destination_ip, exact_field="http.user_agent")
            apply_client_value(source_client, "rtsp_requests", rtsp_request, evidence_type="rtsp_request", protocol="rtsp", direction="outbound", related_ip=destination_ip, exact_field="rtsp.request")
            apply_client_value(source_client, "rtsp_urls", rtsp_url, evidence_type="rtsp_url", protocol="rtsp", direction="outbound", related_ip=destination_ip, exact_field="rtsp.url")
            apply_client_value(source_client, "tls_server_names", server_name, evidence_type="tls_sni", protocol="tls", direction="outbound", related_ip=destination_ip, related_domain=server_name.lower(), exact_field="tls.handshake.extensions_server_name")
            apply_client_value(source_client, "quic_server_names", quic_server_name or http3_authority, evidence_type="quic_sni", protocol="quic", direction="outbound", related_ip=destination_ip, related_domain=(quic_server_name or http3_authority).lower(), exact_field="gquic.tag.sni")
            apply_client_value(source_client, "tls_ja3_fingerprints", tls_ja3, evidence_type="tls_ja3", protocol="tls", direction="outbound", related_ip=destination_ip, exact_field="tls.handshake.ja3")
            apply_client_value(source_client, "tls_ja4_fingerprints", tls_ja4, evidence_type="tls_ja4", protocol="tls", direction="outbound", related_ip=destination_ip, exact_field="tls.handshake.ja4")

            apply_client_value(destination_client, "dns_response_names", response_name, evidence_type="dns_response_name", protocol="dns", direction="inbound", related_ip=source_ip, related_domain=response_name.lower(), exact_field="dns.resp.name")
            apply_client_value(destination_client, "mdns_ptr_names", ptr_name, evidence_type="mdns_ptr", protocol="mdns", direction="inbound", related_ip=source_ip, related_domain=ptr_name.lower(), exact_field="dns.ptr.domain_name")
            apply_client_value(destination_client, "mdns_service_types", mdns_service_type, evidence_type="mdns_service_type", protocol="mdns", direction="inbound", related_ip=source_ip, exact_field="dns.ptr.domain_name")
            apply_client_value(destination_client, "mdns_service_instances", mdns_service_instance, evidence_type="mdns_service_instance", protocol="mdns", direction="inbound", related_ip=source_ip, exact_field="dns.ptr.domain_name")
            apply_client_value(destination_client, "http_server_headers", http_server or http3_server, evidence_type="http_server", protocol="http", direction="inbound", related_ip=source_ip, exact_field="http.server")
            apply_client_value(destination_client, "tls_certificate_subjects", tls_subject, evidence_type="tls_certificate_subject", protocol="tls", direction="inbound", related_ip=source_ip, exact_field="ssl.log.subject")
            apply_client_value(destination_client, "tls_certificate_issuers", tls_issuer, evidence_type="tls_certificate_issuer", protocol="tls", direction="inbound", related_ip=source_ip, exact_field="ssl.log.issuer")
            apply_client_value(destination_client, "tls_ja3s_fingerprints", tls_ja3s, evidence_type="tls_ja3s", protocol="tls", direction="inbound", related_ip=source_ip, exact_field="tls.handshake.ja3s")
            for san in tls_subject_alt_names[:8]:
                apply_client_value(destination_client, "tls_subject_alt_names", san, evidence_type="tls_subject_alt_name", protocol="tls", direction="inbound", related_ip=source_ip, related_domain=san.lower(), exact_field="x509ce.dNSName")

            for client in filter(None, [source_client, destination_client]):
                for domain in resolved_domains[:8]:
                    self._append_profile_count(client, "resolved_domain_counts", domain)
                    self._update_history_profile("clients", str(client.get("mac") or ""), "recurring_domains", domain, now)
                self._apply_history_profiles("clients", str(client.get("mac") or ""), client)
                if protocol_summary:
                    client["protocol_summary"] = dict(protocol_summary)

        for service in service_inventory or []:
            source = str(service.get("source") or "").lower()
            destination = str(service.get("destination") or "").lower()
            evidence_pcap = str(service.get("pcap_path") or pcap_path or "")
            service_name = str(service.get("service_name") or "").strip()
            service_port = int(service.get("service_port") or 0)
            transport = str(service.get("transport") or "").strip()
            protocol_source = str(service.get("protocol_source") or service.get("source") or "").strip()
            evidence_detail = str(service.get("evidence_detail") or "").strip()
            direction = str(service.get("direction") or "outbound").strip().lower()
            target_client = self.clients.get(source)
            if target_client:
                self._append_service_inventory(target_client, service)
                self._record_evidence(
                    target_client,
                    evidence_type=service_name or "service",
                    value=evidence_detail or service_name,
                    protocol=service_name or "service",
                    direction=direction,
                    source=protocol_source,
                    pcap_path=evidence_pcap,
                    exact_field="service_inventory",
                    related_ip=destination,
                )
                self._append_profile_count(target_client, "service_name_counts", service_name or evidence_detail)
                self._update_history_profile("clients", str(target_client.get("mac") or ""), "recurring_services", service_name or evidence_detail, now)
                self._propagate_client_evidence_to_network(
                    target_client,
                    evidence_type=service_name or "service",
                    value=evidence_detail or service_name,
                    protocol=service_name or "service",
                    direction=direction,
                    source=protocol_source,
                    pcap_path=evidence_pcap,
                    exact_field=f"{transport}:{service_port}",
                    related_ip=destination,
                )
                if protocol_summary:
                    target_client["protocol_summary"] = dict(protocol_summary)
                self._apply_history_profiles("clients", str(target_client.get("mac") or ""), target_client)
        self._save_history()

    def get_networks(self) -> List[Dict[str, Any]]:
        return sorted(self.networks.values(), key=lambda item: (item.get("last_seen") or 0, item.get("packet_count") or 0), reverse=True)

    def get_clients(self) -> List[Dict[str, Any]]:
        return sorted(self.clients.values(), key=lambda item: (item.get("last_seen") or 0, item.get("packet_count") or 0), reverse=True)

    def get_authentication_evidence(self) -> Dict[str, Any]:
        return self.auth_tracker.summary()

    def get_channel_activity(self) -> Dict[int, Dict[str, Any]]:
        return {int(channel): dict(stats) for channel, stats in self.channel_activity.items()}

    def get_observation_audit(self) -> Dict[str, Any]:
        networks = self.get_networks()
        channel_activity = self.get_channel_activity()
        auth_evidence = self.get_authentication_evidence()
        coverage_rows = []
        strong_coverage = 0
        weak_coverage = 0
        for network in networks:
            if network.get("synthetic_identity"):
                continue
            visits = int(network.get("observation_capture_count") or 0)
            retained_frames = int(network.get("frame_count_total") or network.get("packet_count") or 0)
            opportunity_score = int((network.get("observation_opportunity") or {}).get("score") or 0)
            evidence_quality = str(network.get("authentication_evidence_quality") or "NONE")
            if visits >= 3 and retained_frames >= 25:
                strong_coverage += 1
            if visits <= 1 and opportunity_score >= 50:
                weak_coverage += 1
            coverage_rows.append(
                {
                    "ssid": network.get("ssid") or "<hidden>",
                    "bssid": network.get("bssid") or "",
                    "channel": network.get("channel"),
                    "visits": visits,
                    "retained_frame_count": retained_frames,
                    "observed_eapol_session_count": int(network.get("authentication_evidence_session_count") or 0),
                    "observed_eapol_frame_count": int(network.get("authentication_evidence_frame_count") or network.get("handshake_eapol_count") or 0),
                    "observation_opportunity": network.get("observation_opportunity") or {},
                    "evidence_quality": evidence_quality,
                }
            )
        coverage_rows.sort(
            key=lambda item: (
                int(item.get("observed_eapol_session_count") or 0),
                int((item.get("observation_opportunity") or {}).get("score") or 0),
                int(item.get("retained_frame_count") or 0),
            ),
            reverse=True,
        )
        total_channel_frames = sum(int((stats or {}).get("frames") or 0) for stats in channel_activity.values())
        total_channel_visits = sum(int((stats or {}).get("captures") or 0) for stats in channel_activity.values())
        active_channels = sum(1 for stats in channel_activity.values() if int((stats or {}).get("frames") or 0) > 0)
        if total_channel_visits >= 20 and total_channel_frames >= 400 and weak_coverage == 0:
            confidence = "STRONG"
        elif total_channel_visits >= 10 and total_channel_frames >= 150:
            confidence = "MODERATE"
        else:
            confidence = "WEAK"
        return {
            "coverage_confidence": {
                "level": confidence,
                "summary": (
                    "Strong observation coverage across visited channels."
                    if confidence == "STRONG"
                    else "Moderate coverage; some SSIDs may still be under-observed."
                    if confidence == "MODERATE"
                    else "Weak coverage; zero evidence is not conclusive."
                ),
                "active_channel_count": active_channels,
                "total_channel_visits": total_channel_visits,
                "total_channel_frames": total_channel_frames,
                "strong_coverage_network_count": strong_coverage,
                "weak_coverage_network_count": weak_coverage,
            },
            "recent_captures": list(self.timeline[:12]),
            "top_ssids": coverage_rows[:12],
            "auth_debug": auth_evidence.get("debug") or {},
        }
