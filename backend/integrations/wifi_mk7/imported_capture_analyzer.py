from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from backend.integrations.wifi_mk7.authentication_evidence_tracker import AuthenticationEvidenceTracker
from backend.integrations.wifi_mk7.packet_capture import PacketCaptureEngine
from backend.integrations.wifi_mk7.wifi_device_tracker import WiFiDeviceTracker
from backend.integrations.wifi_mk7.wifi_intelligence_engine import WiFiIntelligenceEngine


class ImportedCaptureAnalyzer:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.capture = PacketCaptureEngine(root_dir)
        self.intelligence = WiFiIntelligenceEngine()
        self.audit_log_path = self.root_dir / "logs" / "wifi_mk7" / "imported_capture_audit.jsonl"

    def analyze(self, capture_path: str, replay: bool = False) -> Dict[str, Any]:
        path = Path(capture_path).expanduser()
        if not path.exists() or not path.is_file():
            result = {"ok": False, "error": "Capture file not found.", "path": str(path)}
            self._append_audit_entry(path=path, replay=replay, ok=False, error=result["error"])
            return result
        if path.suffix.lower() not in {".pcap", ".pcapng"}:
            result = {"ok": False, "error": "Only .pcap and .pcapng files are supported.", "path": str(path)}
            self._append_audit_entry(path=path, replay=replay, ok=False, error=result["error"])
            return result

        parsed = self.capture.parse_capture_file(str(path))
        if not parsed.get("ok"):
            result = {"ok": False, "error": parsed.get("error") or "Unable to parse capture.", "path": str(path)}
            self._append_audit_entry(path=path, replay=replay, ok=False, error=result["error"])
            return result

        frames = list(parsed.get("frames") or [])
        tracker = WiFiDeviceTracker()
        tracker.ingest_capture(channel=0, band="Imported", pcap_path=str(path), frames=frames)
        networks = self.intelligence.enrich_networks(tracker.get_networks(), tracker.get_clients())
        clients = self.intelligence.enrich_clients(tracker.get_clients())
        evidence = AuthenticationEvidenceTracker().process_frames(frames)
        report = self._report(networks, clients, evidence, path)

        result = {
            "ok": True,
            "path": str(path),
            "replay_mode": bool(replay),
            "frame_count": len(frames),
            "network_count": len(networks),
            "client_count": len(clients),
            "authentication_evidence": evidence,
            "networks": networks,
            "clients": clients,
            "report": report,
        }
        self._append_audit_entry(
            path=path,
            replay=replay,
            ok=True,
            frame_count=len(frames),
            network_count=len(networks),
            client_count=len(clients),
            evidence_session_count=int(evidence.get("session_count") or 0),
            confirmed_session_count=int(((evidence.get("quality_counts") or {}).get("CONFIRMED") or 0)),
        )
        return result

    def _report(self, networks: list[Dict[str, Any]], clients: list[Dict[str, Any]], evidence: Dict[str, Any], path: Path) -> Dict[str, Any]:
        critical = [item for item in networks if str((item.get("password_risk") or {}).get("risk")) == "CRITICAL"]
        high_opp = [item for item in networks if str((item.get("observation_opportunity") or {}).get("level")) == "HIGH"]
        return {
            "title": "WiFi Security Assessment Report",
            "capture_name": path.name,
            "summary": {
                "networks": len(networks),
                "clients": len(clients),
                "evidence_sessions": int((evidence.get("session_count") or 0)),
                "confirmed_evidence": int(((evidence.get("quality_counts") or {}).get("CONFIRMED") or 0)),
                "likely_evidence": int(((evidence.get("quality_counts") or {}).get("LIKELY") or 0)),
                "critical_password_risk": len(critical),
                "high_observation_opportunity": len(high_opp),
            },
            "top_networks": [
                {
                    "ssid": item.get("ssid") or "<hidden>",
                    "bssid": item.get("bssid") or "unresolved",
                    "security": item.get("security") or "--",
                    "authentication_evidence": (item.get("authentication_evidence") or {}).get("summary") or "--",
                    "password_risk": (item.get("password_risk") or {}).get("risk") or "--",
                    "reasons": (item.get("password_risk") or {}).get("reasons") or [],
                    "recommendations": self._recommendations(item),
                }
                for item in sorted(
                    networks,
                    key=lambda network: (
                        int(((network.get("password_risk") or {}).get("score") or 0)),
                        int(((network.get("observation_opportunity") or {}).get("score") or 0)),
                    ),
                    reverse=True,
                )[:10]
            ],
        }

    @staticmethod
    def _recommendations(network: Dict[str, Any]) -> list[str]:
        recommendations: list[str] = []
        security = str(network.get("security") or "").upper()
        pmf_enabled = str(network.get("pmf") or "").lower() in {"true", "1", "required", "capable"}
        posture = network.get("security_posture") or {}
        if "WPA2" in security and "WPA3" not in security:
            recommendations.append("Upgrade to WPA3 where supported.")
        if not pmf_enabled and "OPEN" not in security:
            recommendations.append("Enable PMF for stronger management-frame protection.")
        if posture.get("wps_present"):
            recommendations.append("Disable WPS unless explicitly required for a controlled deployment.")
        recommendations.append("Review passphrase policy and remove any default ISP/OEM credentials.")
        return recommendations

    def _append_audit_entry(self, *, path: Path, replay: bool, ok: bool, error: str = "", **metadata: Any) -> None:
        entry = {
            "timestamp": int(time.time()),
            "path": str(path),
            "replay_mode": bool(replay),
            "ok": bool(ok),
            "error": str(error or ""),
            **metadata,
        }
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        except OSError:
            pass
