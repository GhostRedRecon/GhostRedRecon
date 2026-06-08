from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple


class AuthenticationEvidenceTracker:
    MAX_STORED_FRAMES_PER_SESSION = 16

    def __init__(self) -> None:
        self.sessions: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.raw_eapol_frame_count = 0
        self.duplicate_eapol_frame_count = 0
        self.unmatched_eapol_frame_count = 0

    @staticmethod
    def _normalize_mac(value: Any) -> str:
        return str(value or "").strip().lower()

    @classmethod
    def _resolve_client_mac(cls, frame: Dict[str, Any], bssid: str) -> str:
        source = cls._normalize_mac(frame.get("source") or frame.get("transmitter"))
        destination = cls._normalize_mac(frame.get("destination") or frame.get("receiver"))
        receiver = cls._normalize_mac(frame.get("receiver"))
        transmitter = cls._normalize_mac(frame.get("transmitter"))

        candidates = [
            item for item in (source, destination, transmitter, receiver)
            if item and item != bssid and item != "ff:ff:ff:ff:ff:ff"
        ]
        if not candidates:
            return ""

        if source == bssid and destination and destination != bssid:
            return destination
        if destination == bssid and source and source != bssid:
            return source
        if transmitter == bssid and receiver and receiver != bssid:
            return receiver
        if receiver == bssid and transmitter and transmitter != bssid:
            return transmitter
        return candidates[0]

    @staticmethod
    def _frame_signature(frame: Dict[str, Any]) -> Tuple[Any, ...]:
        timestamp = round(float(frame.get("timestamp") or 0.0), 6)
        return (
            timestamp,
            str(frame.get("eapol_type") or ""),
            int(frame.get("sequence_number") or -1),
            str(frame.get("source") or frame.get("transmitter") or "").lower(),
            str(frame.get("destination") or frame.get("receiver") or "").lower(),
        )

    @staticmethod
    def _session_key(frame: Dict[str, Any]) -> Tuple[str, str] | None:
        bssid = AuthenticationEvidenceTracker._normalize_mac(frame.get("bssid"))
        client_mac = AuthenticationEvidenceTracker._resolve_client_mac(frame, bssid)
        if not bssid or not client_mac:
            return None
        return (bssid, client_mac)

    def process_frames(self, frames: List[Dict[str, Any]], pcap_path: str = "") -> Dict[str, Any]:
        for frame in frames:
            if not frame.get("eapol_type"):
                continue
            self.raw_eapol_frame_count += 1
            key = self._session_key(frame)
            if key is None:
                self.unmatched_eapol_frame_count += 1
                continue
            session = self.sessions.setdefault(
                key,
                {
                    "bssid": key[0],
                    "client_mac": key[1],
                    "frames": [],
                    "frame_count_total": 0,
                    "eapol_types": set(),
                    "frame_signatures": set(),
                    "participants": set(),
                    "message_numbers": set(),
                    "replay_counters": set(),
                    "start_time": float(frame.get("timestamp") or 0.0),
                    "last_time": float(frame.get("timestamp") or 0.0),
                    "channel": frame.get("channel"),
                    "ssid": frame.get("ssid") or "",
                },
            )
            signature = self._frame_signature(frame)
            if signature in session["frame_signatures"]:
                self.duplicate_eapol_frame_count += 1
                continue
            session["frame_signatures"].add(signature)
            session["frame_count_total"] = int(session.get("frame_count_total") or 0) + 1
            if len(session["frames"]) < self.MAX_STORED_FRAMES_PER_SESSION:
                session["frames"].append(
                    {
                        **frame,
                        "pcap_path": str(frame.get("pcap_path") or pcap_path or ""),
                    }
                )
            session["last_time"] = float(frame.get("timestamp") or session["last_time"])
            if frame.get("eapol_type"):
                session["eapol_types"].add(str(frame.get("eapol_type")))
            session["participants"].add(self._normalize_mac(frame.get("source") or frame.get("transmitter")))
            session["participants"].add(self._normalize_mac(frame.get("destination") or frame.get("receiver")))
            message_number = frame.get("eapol_message_number")
            if message_number is not None:
                try:
                    session["message_numbers"].add(int(message_number))
                except Exception:
                    pass
            replay_counter = frame.get("eapol_replay_counter")
            if replay_counter is not None:
                try:
                    session["replay_counters"].add(int(replay_counter))
                except Exception:
                    pass

        return self.summary()

    @staticmethod
    def classify_session(session: Dict[str, Any]) -> str:
        frame_count = int(session.get("frame_count_total") or len(session.get("frames") or []))
        start_time = float(session.get("start_time") or 0.0)
        last_time = float(session.get("last_time") or start_time)
        duration = max(0.0, last_time - start_time)
        participants = {item for item in (session.get("participants") or set()) if item}
        bidirectional = len(participants) >= 2
        message_numbers = {int(item) for item in (session.get("message_numbers") or set()) if item is not None}
        replay_counters = {int(item) for item in (session.get("replay_counters") or set()) if item is not None}
        has_all_key_messages = {1, 2, 3, 4}.issubset(message_numbers)
        has_three_key_messages = len(message_numbers.intersection({1, 2, 3, 4})) >= 3
        has_two_key_messages = len(message_numbers.intersection({1, 2, 3, 4})) >= 2
        if has_all_key_messages or frame_count >= 4:
            return "CONFIRMED"
        if has_three_key_messages:
            return "LIKELY"
        if frame_count >= 3 and (bidirectional or duration <= 3.0 or len(replay_counters) >= 2):
            return "LIKELY"
        if has_two_key_messages and (bidirectional or len(replay_counters) >= 1):
            return "LIKELY"
        if frame_count >= 2 and (bidirectional or len(replay_counters) >= 1):
            return "LIKELY"
        if frame_count >= 1:
            return "PARTIAL"
        return "NONE"

    def summary(self) -> Dict[str, Any]:
        sessions: List[Dict[str, Any]] = []
        quality_counts = defaultdict(int)
        unique_bssids = set()
        unique_clients = set()
        total_frame_count = 0
        for session in self.sessions.values():
            quality = self.classify_session(session)
            quality_counts[quality] += 1
            unique_bssids.add(session["bssid"])
            unique_clients.add(session["client_mac"])
            frame_count = int(session.get("frame_count_total") or len(session.get("frames") or []))
            total_frame_count += frame_count
            sessions.append(
                {
                    "bssid": session["bssid"],
                    "client_mac": session["client_mac"],
                    "ssid": session.get("ssid") or "",
                    "channel": session.get("channel"),
                    "frame_count": frame_count,
                    "eapol_types": sorted(session.get("eapol_types") or []),
                    "message_numbers": sorted(int(item) for item in (session.get("message_numbers") or set()) if item is not None),
                    "replay_counter_count": len(session.get("replay_counters") or set()),
                    "quality": quality,
                    "start_time": session.get("start_time"),
                    "last_time": session.get("last_time"),
                    "bidirectional": len({item for item in (session.get("participants") or set()) if item}) >= 2,
                    "evidence_refs": [
                        {
                            "pcap_file": str(frame.get("pcap_path") or ""),
                            "frame_number": int(frame.get("frame_number") or 0),
                            "timestamp": float(frame.get("timestamp") or 0.0),
                            "message_number": frame.get("eapol_message_number"),
                        }
                        for frame in list(session.get("frames") or [])[:16]
                    ],
                }
            )

        sessions.sort(key=lambda item: (item["frame_count"], item["last_time"] or 0), reverse=True)
        return {
            "session_count": len(sessions),
            "network_count": len(unique_bssids),
            "client_count": len(unique_clients),
            "total_frame_count": total_frame_count,
            "quality_counts": {
                "NONE": int(quality_counts.get("NONE", 0)),
                "PARTIAL": int(quality_counts.get("PARTIAL", 0)),
                "LIKELY": int(quality_counts.get("LIKELY", 0)),
                "CONFIRMED": int(quality_counts.get("CONFIRMED", 0)),
            },
            "debug": {
                "raw_eapol_frame_count": int(self.raw_eapol_frame_count),
                "duplicate_eapol_frame_count": int(self.duplicate_eapol_frame_count),
                "unmatched_eapol_frame_count": int(self.unmatched_eapol_frame_count),
                "deduplicated_eapol_frame_count": max(0, int(self.raw_eapol_frame_count) - int(self.duplicate_eapol_frame_count)),
            },
            "sessions": sessions[:50],
        }
