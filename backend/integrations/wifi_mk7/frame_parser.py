from __future__ import annotations

import binascii
from typing import Any, Dict, List


class FrameParser:
    SUBTYPE_LABELS = {
        "0x0008": "beacon",
        "0x0004": "probe_request",
        "0x0005": "probe_response",
        "0x0000": "association_request",
        "0x0001": "association_response",
        "0x0002": "reassociation_request",
        "0x0003": "reassociation_response",
        "0x000a": "disassociation",
        "0x000b": "authentication",
        "0x000c": "deauthentication",
    }

    def _normalize_subtype(self, value: str) -> str:
        raw = str(value or "").strip().lower()
        if raw.startswith("0x"):
            return raw
        try:
            return f"0x{int(raw):04x}"
        except Exception:
            return raw

    def _security_label(self, privacy: str, akm: str, cipher: str) -> str:
        privacy_enabled = str(privacy or "0").strip() not in {"", "0", "false", "False"}
        akm_lower = str(akm or "").lower()
        cipher_lower = str(cipher or "").lower()
        if "sae" in akm_lower:
            return "WPA3"
        if akm_lower or cipher_lower:
            return "WPA2"
        if privacy_enabled:
            return "Protected"
        return "Open"

    def _first_value(self, value: str) -> str:
        raw = self._clean_text(value)
        if not raw:
            return ""
        return raw.split(",", 1)[0].strip()

    def _clean_text(self, value: str) -> str:
        raw = str(value or "").strip()
        if raw in {"<MISSING>", "<missing>", "(null)", "null", "None"}:
            return ""
        return raw

    def _float_value(self, value: str) -> float | None:
        raw = self._first_value(value)
        if not raw:
            return None
        try:
            return float(raw)
        except Exception:
            return None

    def _int_value(self, value: str) -> int | None:
        raw = self._first_value(value)
        if not raw:
            return None
        try:
            return int(raw)
        except Exception:
            return None

    def _decode_ssid(self, value: str) -> str:
        raw = self._clean_text(value)
        if not raw:
            return ""
        if len(raw) % 2 == 0:
            try:
                decoded = binascii.unhexlify(raw).decode("utf-8", errors="ignore").strip("\x00")
                if decoded:
                    return decoded
            except Exception:
                pass
        return raw

    def _bool_value(self, value: str) -> bool:
        raw = self._first_value(value).lower()
        return raw in {"1", "true", "yes", "set"}

    def _hex_or_int_value(self, value: str) -> int | None:
        raw = self._first_value(value)
        if not raw:
            return None
        try:
            if str(raw).lower().startswith("0x"):
                return int(raw, 16)
            return int(raw)
        except Exception:
            return None

    def parse_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        frames: List[Dict[str, Any]] = []
        for line in lines:
            parts = (line or "").split("\t")
            if len(parts) < 12:
                continue
            while len(parts) < 50:
                parts.append("")
            subtype = self._normalize_subtype(parts[2])
            frames.append(
                {
                    "frame_number": self._int_value(parts[0]),
                    "timestamp": float(parts[1] or 0.0),
                    "subtype": subtype,
                    "subtype_label": self.SUBTYPE_LABELS.get(subtype, "other"),
                    "transmitter": parts[3] or "",
                    "source": parts[4] or "",
                    "destination": parts[5] or "",
                    "receiver": parts[6] or "",
                    "bssid": parts[7] or "",
                    "ssid": self._decode_ssid(parts[8]),
                    "rssi_dbm": self._float_value(parts[9]),
                    "channel": self._int_value(parts[10]),
                    "frequency_mhz": self._int_value(parts[11]),
                    "security": self._security_label(parts[12], parts[13], parts[14] if len(parts) > 14 else ""),
                    "privacy": parts[12],
                    "akm": parts[13],
                    "cipher": parts[14] if len(parts) > 14 else "",
                    "pmf": parts[15] if len(parts) > 15 else "",
                    "pmf_capable": self._bool_value(parts[16] if len(parts) > 16 else ""),
                    "wps_manufacturer": parts[17] if len(parts) > 17 else "",
                    "wps_model_name": parts[18] if len(parts) > 18 else "",
                    "wps_device_name": parts[19] if len(parts) > 19 else "",
                    "supported_rates": self._first_value(parts[20] if len(parts) > 20 else ""),
                    "extended_supported_rates": self._first_value(parts[21] if len(parts) > 21 else ""),
                    "frame_len": self._int_value(parts[22] if len(parts) > 22 else ""),
                    "frame_type": self._int_value(parts[23] if len(parts) > 23 else ""),
                    "retry": self._bool_value(parts[24] if len(parts) > 24 else ""),
                    "sequence_number": self._int_value(parts[25] if len(parts) > 25 else ""),
                    "qos_priority": self._int_value(parts[26] if len(parts) > 26 else ""),
                    "data_rate_mbps": self._float_value(parts[27] if len(parts) > 27 else ""),
                    "ht_capabilities": self._first_value(parts[28] if len(parts) > 28 else ""),
                    "vht_capabilities": self._first_value(parts[29] if len(parts) > 29 else ""),
                    "he_capable": self._bool_value(parts[30] if len(parts) > 30 else ""),
                    "wps_model_number": self._clean_text(parts[31] if len(parts) > 31 else ""),
                    "wps_serial_number": self._clean_text(parts[32] if len(parts) > 32 else ""),
                    "wps_config_methods": self._first_value(parts[33] if len(parts) > 33 else ""),
                    "wps_rf_bands": self._first_value(parts[34] if len(parts) > 34 else ""),
                    "wps_primary_device_camera": self._bool_value(parts[35] if len(parts) > 35 else ""),
                    "dhcp_hostname": self._clean_text(parts[36] if len(parts) > 36 else ""),
                    "eapol_type": self._first_value(parts[37] if len(parts) > 37 else ""),
                    "eapol_key_descriptor_type": self._int_value(parts[38] if len(parts) > 38 else ""),
                    "eapol_key_length": self._int_value(parts[39] if len(parts) > 39 else ""),
                    "eapol_replay_counter": self._int_value(parts[40] if len(parts) > 40 else ""),
                    "eapol_message_number": self._int_value(parts[41] if len(parts) > 41 else ""),
                    "eapol_key_info": self._hex_or_int_value(parts[42] if len(parts) > 42 else ""),
                    "eapol_key_ack": self._bool_value(parts[43] if len(parts) > 43 else ""),
                    "eapol_key_mic": self._bool_value(parts[44] if len(parts) > 44 else ""),
                    "eapol_secure": self._bool_value(parts[45] if len(parts) > 45 else ""),
                    "eapol_install": self._bool_value(parts[46] if len(parts) > 46 else ""),
                    "eapol_request": self._bool_value(parts[47] if len(parts) > 47 else ""),
                    "eapol_encrypted_key_data": self._bool_value(parts[48] if len(parts) > 48 else ""),
                    "eapol_key_data_length": self._int_value(parts[49] if len(parts) > 49 else ""),
                }
            )
        return frames
