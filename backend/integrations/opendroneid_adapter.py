from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List


class OpenDroneIDAdapter:
    TOKEN_TO_VENDOR = {
        "dji": "DJI",
        "autel": "Autel",
        "parrot": "Parrot",
        "skydio": "Skydio",
        "tello": "Ryze / DJI",
        "opendroneid": "OpenDroneID",
        "remote id": "Remote ID",
        "remoteid": "Remote ID",
    }
    ODID_TOKENS = (
        "opendroneid",
        "remote id",
        "remoteid",
        "uas",
        "uav",
        "drone",
        "faa rid",
        "astm",
    )
    DRONE_VENDOR_TOKENS = ("dji", "autel", "parrot", "skydio", "tello", "ryze", "yuneec")

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = Path(root_dir)

    @staticmethod
    def _normalize_text(value: Any) -> str:
        return str(value or "").strip()

    def _vendor_from_blob(self, blob: str) -> str:
        lowered = blob.lower()
        for token, vendor in self.TOKEN_TO_VENDOR.items():
            if token in lowered:
                return vendor
        return ""

    def _pcap_remote_id_artifacts(self, pcap_inventory: List[Dict[str, Any]], tshark_path: str) -> List[Dict[str, Any]]:
        if not tshark_path:
            return []
        artifacts: List[Dict[str, Any]] = []
        for entry in (pcap_inventory or [])[:6]:
            pcap_path = str(entry.get("path") or "").strip()
            if not pcap_path or not Path(pcap_path).exists():
                continue
            try:
                result = subprocess.run(
                    [
                        tshark_path,
                        "-r",
                        pcap_path,
                        "-Y",
                        "wlan.fc.type_subtype == 8 or wlan.fc.type_subtype == 5",
                        "-T",
                        "fields",
                        "-E",
                        "header=n",
                        "-E",
                        "separator=\t",
                        "-e",
                        "frame.time_epoch",
                        "-e",
                        "wlan.bssid",
                        "-e",
                        "wlan.ssid",
                        "-e",
                        "wlan_radio.channel",
                        "-e",
                        "radiotap.dbm_antsignal",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except Exception:
                continue
            if result.returncode != 0:
                continue
            for raw in (result.stdout or "").splitlines():
                parts = raw.split("\t")
                while len(parts) < 5:
                    parts.append("")
                ts_text, bssid, ssid, channel, rssi = parts[:5]
                ssid_text = self._normalize_text(ssid)
                blob = f"{ssid_text} {bssid}"
                if not any(token in blob.lower() for token in self.ODID_TOKENS) and not any(token in blob.lower() for token in self.DRONE_VENDOR_TOKENS):
                    continue
                artifacts.append(
                    {
                        "timestamp": float(ts_text or 0.0),
                        "bssid": self._normalize_text(bssid).lower(),
                        "ssid": ssid_text,
                        "channel": channel,
                        "rssi_dbm": rssi,
                        "pcap_path": pcap_path,
                    }
                )
        return artifacts

    def decode(
        self,
        observations: List[Dict[str, Any]],
        pcap_inventory: List[Dict[str, Any]],
        tshark_path: str = "",
    ) -> Dict[str, Any]:
        artifacts = self._pcap_remote_id_artifacts(pcap_inventory, tshark_path)
        by_bssid = {str(item.get("bssid") or "").strip().lower(): item for item in artifacts if item.get("bssid")}
        targets: List[Dict[str, Any]] = []
        parsed_objects: List[Dict[str, Any]] = []
        for item in observations:
            ssid = self._normalize_text(item.get("ssid"))
            vendor = self._normalize_text(item.get("vendor") or item.get("oui_vendor"))
            bssid = self._normalize_text(item.get("bssid") or item.get("associated_bssid") or item.get("mac")).lower()
            blob = f"{ssid} {vendor} {bssid}".lower()
            token_hits = [token for token in self.ODID_TOKENS if token in blob]
            vendor_hits = [token for token in self.DRONE_VENDOR_TOKENS if token in blob]
            pcap_hit = by_bssid.get(bssid) or {}
            if not token_hits and not vendor_hits and not pcap_hit:
                continue
            confidence = 50
            reasons: List[str] = []
            classification = "Probable Drone"
            proof_level = "wifi_candidate"
            if token_hits:
                confidence += 22
                reasons.append(f"SSID/identifier contains Remote ID markers: {', '.join(token_hits[:3])}.")
                classification = "Confirmed Drone"
                proof_level = "wifi_remote_id_candidate"
            if vendor_hits:
                confidence += 16
                reasons.append(f"SSID/vendor contains drone-family tokens: {', '.join(vendor_hits[:3])}.")
            if pcap_hit:
                confidence += 10
                reasons.append("Beacon/probe evidence retained in Wi-Fi capture.")
            packet_count = int(item.get("packet_count") or 0)
            if packet_count >= 15:
                confidence += 8
                reasons.append("Repeated Wi-Fi management recurrence.")
            manufacturer = self._vendor_from_blob(blob) or vendor or "Unknown"
            label = ssid or f"{manufacturer} Remote ID Source"
            parsed_object = {
                "object_type": "remote_id_candidate",
                "transport": "wifi_beacon_or_probe",
                "identifier": bssid or "--",
                "ssid": ssid or "<hidden>",
                "manufacturer": manufacturer,
                "token_hits": token_hits,
                "vendor_hits": vendor_hits,
                "pcap_reference": str(pcap_hit.get("pcap_path") or ""),
                "timestamp": float(pcap_hit.get("timestamp") or 0.0),
            }
            parsed_objects.append(parsed_object)
            targets.append(
                {
                    "target_id": f"odid-{bssid.replace(':', '')[:12] or abs(hash(label)) % 100000}",
                    "label": label,
                    "classification": classification,
                    "target_type": "confirmed_drone" if classification == "Confirmed Drone" else "probable_drone",
                    "confidence": max(55, min(92, confidence)),
                    "manufacturer": manufacturer,
                    "model_family": "OpenDroneID / Wi-Fi Broadcast",
                    "proof_level": proof_level,
                    "identifier": bssid or "--",
                    "family_label": manufacturer if manufacturer != "Unknown" else "Open Drone ID Family",
                    "decoder": {
                        "name": "OpenDroneID Adapter",
                        "status": "decoded" if token_hits else "candidate",
                        "rationale": reasons,
                        "parsed_object": parsed_object,
                    },
                    "evidence": [
                        {
                            "artifact_type": "wifi_remote_id_candidate",
                            "sensor": "MK7AC",
                            "reference": str(pcap_hit.get("pcap_path") or ""),
                            "timestamp": float(pcap_hit.get("timestamp") or 0.0),
                        }
                    ],
                    "reasons": reasons,
                }
            )
        manifest = {
            "decoder": "OpenDroneID Adapter",
            "target_count": len(targets),
            "targets": targets,
            "pcap_artifacts": artifacts[:20],
            "parsed_objects": parsed_objects[:32],
            "decoder_diagnostics": {
                "status": "structured_passive_parse",
                "artifact_count": len(artifacts),
                "parsed_object_count": len(parsed_objects),
            },
        }
        return manifest

    @staticmethod
    def write_manifest(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
