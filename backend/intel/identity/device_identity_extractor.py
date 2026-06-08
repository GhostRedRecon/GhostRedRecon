# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/device_identity_extractor.py
# VERSION:      v2.0.0 (SIGINT IDENTITY EXTRACTION ENGINE)
# UPDATED:      2026-03-24
# =============================================================================

"""
🧠 DEVICE IDENTITY EXTRACTOR (PHASE 4 CORE)

ARCHITECTURE
----------------------------------------------------------------------------
SignalEngine
    ↓
DeviceIdentityExtractor  ← THIS FILE
    ↓
Device Fusion / Device Intelligence / API

This module converts protocol-aware metadata into identity-bearing device
artifacts suitable for Phase 4 SIGINT workflows.

----------------------------------------------------------------------------
🎯 PURPOSE
----------------------------------------------------------------------------
Turn weak protocol observations into structured identity evidence.

This engine is responsible for:
- extracting primary identifiers (MAC / BD_ADDR / DevEUI / DevAddr / device_id)
- extracting secondary identifiers (UUID / SSID / device name / manufacturer data)
- normalizing identifiers into stable canonical form
- validating identifier quality
- assigning identity type + identity source
- deriving vendor hints from OUI when possible
- generating fallback RF fingerprints when direct IDs are absent
- assigning evidence-based confidence
- preserving a safe, non-destructive output contract for SignalEngine

----------------------------------------------------------------------------
✅ DESIGN PRINCIPLES
----------------------------------------------------------------------------
1. NON-DESTRUCTIVE
   Never mutates the incoming signal object.

2. CONTRACT-STABLE
   extract(signal) -> dict remains unchanged.

3. FAIL-SAFE
   Bad metadata must never crash the runtime.

4. EVIDENCE-FIRST
   Confidence is based on observed evidence, not hardcoded blind trust.

5. SIGINT-REALISTIC
   Prefer normalized identity, vendor hints, and RF fallback over empty output.

6. THREAD-SAFE
   Stateless extractor; safe for repeated use from runtime threads.

----------------------------------------------------------------------------
⚠️ IMPORTANT
----------------------------------------------------------------------------
This module does NOT decode packets or frames directly.

It relies on upstream metadata supplied by:
- protocol classifiers
- burst decoders
- BLE parsers
- Wi-Fi parsers
- LoRa parsers
- Sub-GHz pattern extractors

If upstream metadata is weak, this engine will fall back to partial identity
or RF fingerprint identity rather than fabricating certainty.

----------------------------------------------------------------------------
📤 OUTPUT SCHEMA
----------------------------------------------------------------------------
{
    "primary_id": Optional[str],
    "secondary_id": Optional[dict],
    "identity_type": Optional[str],
    "identity_source": Optional[str],
    "confidence": float,
    "vendor": Optional[str],
    "vendor_oui": Optional[str],
    "fingerprint_id": Optional[str],
    "evidence": list[str],
    "timestamp": float
}
----------------------------------------------------------------------------
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional


class DeviceIdentityExtractor:
    VERSION = "2.0.0"

    # -------------------------------------------------------------------------
    # Minimal built-in OUI map
    # -------------------------------------------------------------------------
    # This is intentionally small and safe. It is a seed layer, not a full DB.
    # You can later replace or extend this with a YAML-backed OUI database.
    OUI_MAP = {
        "00:1A:11": "Google",
        "00:03:7F": "Atheros",
        "00:05:9A": "Cisco",
        "00:09:5B": "Netgear",
        "00:0C:43": "Ralink",
        "00:0F:66": "Samsung",
        "00:11:22": "Cimsys",
        "00:16:6F": "Intel",
        "00:17:88": "Philips",
        "00:1B:63": "Apple",
        "00:1D:D8": "Cisco",
        "00:1E:65": "Samsung",
        "00:21:E8": "Apple",
        "00:23:12": "Apple",
        "00:25:00": "Apple",
        "00:26:08": "Apple",
        "00:50:F2": "Microsoft",
        "18:65:90": "Apple",
        "28:CF:E9": "Apple",
        "3C:5A:B4": "Google",
        "40:4E:36": "HP",
        "44:65:0D": "Apple",
        "58:CB:52": "Google",
        "5C:F3:70": "Apple",
        "60:03:08": "Apple",
        "68:3E:34": "Intel",
        "70:3E:AC": "Apple",
        "74:DA:38": "Google",
        "7C:2F:80": "Samsung",
        "84:38:35": "Samsung",
        "8C:85:90": "Apple",
        "94:65:2D": "Apple",
        "9C:FC:E8": "Samsung",
        "A4:C3:F0": "Apple",
        "AC:BC:32": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "BC:54:36": "Apple",
        "C8:2A:14": "Apple",
        "D8:96:95": "Apple",
        "DC:A6:32": "Raspberry Pi",
        "E0:B5:2D": "Apple",
        "E4:E0:C5": "Samsung",
        "F0:18:98": "Apple",
        "FC:FB:FB": "Apple",
    }

    MAC_12_RE = re.compile(r"^[0-9A-F]{12}$")
    MAC_17_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
    HEX_RE = re.compile(r"^[0-9A-F]+$")
    UUID_RE = re.compile(r"^[0-9A-Fa-f\-]{4,36}$")

    # =========================================================================
    # PUBLIC ENTRYPOINT
    # =========================================================================
    def extract(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main identity extraction entrypoint.

        This function is intentionally fail-safe and always returns a dict
        matching the stable output contract.
        """
        try:
            protocol = str(signal.get("protocol") or "").upper().strip()

            if protocol == "BLE":
                return self._extract_ble(signal)

            if protocol == "WIFI":
                return self._extract_wifi(signal)

            if protocol == "LORA":
                return self._extract_lora(signal)

            if protocol in ["OOK", "FSK", "SUBGHZ", "SUB_GHZ", "ASK"]:
                return self._extract_subghz(signal)

            return self._extract_generic_rf(signal)

        except Exception:
            return self._empty_identity()

    # =========================================================================
    # BLE
    # =========================================================================
    def _extract_ble(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        meta = self._meta(signal)
        evidence: List[str] = []

        raw_addr = (
            meta.get("bd_addr")
            or meta.get("ble_address")
            or meta.get("access_address")
            or meta.get("mac")
            or meta.get("address")
            or meta.get("adv_address")
        )
        bd_addr = self._normalize_mac(raw_addr)

        uuid = self._normalize_uuid(
            meta.get("uuid")
            or meta.get("service_uuid")
            or meta.get("primary_service_uuid")
        )

        name = self._clean_text(
            meta.get("device_name")
            or meta.get("name")
            or meta.get("local_name")
            or meta.get("ble_name")
        )

        manufacturer_data = self._clean_text(
            meta.get("manufacturer_data")
            or meta.get("mfg_data")
            or meta.get("company_data")
        )

        appearance = meta.get("appearance")
        adv_type = meta.get("adv_type") or meta.get("pdu_type")
        addr_type = meta.get("address_type") or meta.get("ble_address_type")

        vendor = self._lookup_vendor_from_mac(bd_addr)
        vendor_oui = self._extract_oui(bd_addr)

        if bd_addr:
            evidence.append("ble_address")
        if uuid:
            evidence.append("service_uuid")
        if name:
            evidence.append("device_name")
        if manufacturer_data:
            evidence.append("manufacturer_data")
        if appearance is not None:
            evidence.append("appearance")
        if adv_type:
            evidence.append("adv_type")
        if vendor:
            evidence.append("vendor_oui")

        primary_id = bd_addr
        fingerprint_id = None

        if not primary_id:
            fingerprint_id = self._build_fingerprint_id(
                protocol="BLE",
                fields=[
                    signal.get("frequency_mhz"),
                    uuid,
                    name,
                    manufacturer_data,
                    appearance,
                    adv_type,
                    signal.get("device_type"),
                    meta.get("periodicity"),
                ],
            )
            if fingerprint_id:
                primary_id = fingerprint_id
                evidence.append("rf_fingerprint")

        confidence = self._score_confidence(
            direct_id=bd_addr is not None,
            vendor_present=vendor is not None,
            name_present=name is not None,
            secondary_count=sum(
                1 for x in [uuid, manufacturer_data, appearance, adv_type, addr_type] if x is not None
            ),
            fingerprint_only=(bd_addr is None and fingerprint_id is not None),
        )

        if primary_id:
            return {
                "primary_id": primary_id,
                "secondary_id": {
                    "uuid": uuid,
                    "name": name,
                    "manufacturer_data": manufacturer_data,
                    "appearance": appearance,
                    "adv_type": adv_type,
                    "address_type": addr_type,
                },
                "identity_type": "BLE_DEVICE" if bd_addr else "BLE_RF_FINGERPRINT",
                "identity_source": "BLE_ADV" if bd_addr else "BLE_RF_PATTERN",
                "confidence": confidence,
                "vendor": vendor,
                "vendor_oui": vendor_oui,
                "fingerprint_id": fingerprint_id,
                "evidence": evidence,
                "timestamp": time.time(),
            }

        return self._empty_identity()

    # =========================================================================
    # WIFI
    # =========================================================================
    def _extract_wifi(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        meta = self._meta(signal)
        evidence: List[str] = []

        raw_mac = (
            meta.get("bssid")
            or meta.get("mac")
            or meta.get("transmitter")
            or meta.get("addr2")
            or meta.get("wifi_mac")
        )
        mac = self._normalize_mac(raw_mac)

        ssid = self._clean_text(meta.get("ssid") or meta.get("essid"))
        if ssid == "":
            ssid = None

        channel = meta.get("wifi_channel") or meta.get("channel")
        frame_type = meta.get("frame_type") or meta.get("subtype") or meta.get("wifi_frame_type")
        encryption = meta.get("encryption") or meta.get("security")
        hidden_ssid = self._safe_bool(meta.get("hidden_ssid"), default=False)

        vendor = self._lookup_vendor_from_mac(mac)
        vendor_oui = self._extract_oui(mac)

        if mac:
            evidence.append("wifi_bssid")
        if ssid:
            evidence.append("ssid")
        if channel is not None:
            evidence.append("channel")
        if frame_type:
            evidence.append("frame_type")
        if encryption:
            evidence.append("security")
        if vendor:
            evidence.append("vendor_oui")
        if hidden_ssid:
            evidence.append("hidden_ssid")

        primary_id = mac
        fingerprint_id = None

        if not primary_id:
            fingerprint_id = self._build_fingerprint_id(
                protocol="WIFI",
                fields=[
                    signal.get("frequency_mhz"),
                    ssid,
                    channel,
                    frame_type,
                    encryption,
                    signal.get("bandwidth_estimate_mhz"),
                    meta.get("periodicity"),
                    meta.get("peak_density"),
                ],
            )
            if fingerprint_id:
                primary_id = fingerprint_id
                evidence.append("rf_fingerprint")

        confidence = self._score_confidence(
            direct_id=mac is not None,
            vendor_present=vendor is not None,
            name_present=ssid is not None,
            secondary_count=sum(1 for x in [channel, frame_type, encryption] if x is not None),
            fingerprint_only=(mac is None and fingerprint_id is not None),
        )

        if primary_id:
            return {
                "primary_id": primary_id,
                "secondary_id": {
                    "ssid": ssid,
                    "channel": channel,
                    "frame_type": frame_type,
                    "encryption": encryption,
                    "hidden_ssid": hidden_ssid,
                },
                "identity_type": "WIFI_DEVICE" if mac else "WIFI_RF_FINGERPRINT",
                "identity_source": "WIFI_BEACON" if mac else "WIFI_RF_PATTERN",
                "confidence": confidence,
                "vendor": vendor,
                "vendor_oui": vendor_oui,
                "fingerprint_id": fingerprint_id,
                "evidence": evidence,
                "timestamp": time.time(),
            }

        return self._empty_identity()

    # =========================================================================
    # LORA
    # =========================================================================
    def _extract_lora(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        meta = self._meta(signal)
        evidence: List[str] = []

        deveui = self._normalize_hex_id(
            meta.get("deveui") or meta.get("dev_eui"),
            expected_lengths={16},
        )
        devaddr = self._normalize_hex_id(
            meta.get("devaddr") or meta.get("dev_addr"),
            expected_lengths={8},
        )
        app_eui = self._normalize_hex_id(
            meta.get("appeui") or meta.get("app_eui"),
            expected_lengths={16},
        )

        spreading_factor = meta.get("sf") or meta.get("spreading_factor")
        bandwidth = meta.get("bw") or meta.get("bandwidth")
        coding_rate = meta.get("cr") or meta.get("coding_rate")

        if deveui:
            evidence.append("deveui")
        if devaddr:
            evidence.append("devaddr")
        if app_eui:
            evidence.append("appeui")
        if spreading_factor is not None:
            evidence.append("spreading_factor")
        if bandwidth is not None:
            evidence.append("bandwidth")
        if coding_rate is not None:
            evidence.append("coding_rate")

        primary_id = deveui or devaddr
        fingerprint_id = None

        if not primary_id:
            fingerprint_id = self._build_fingerprint_id(
                protocol="LORA",
                fields=[
                    signal.get("frequency_mhz"),
                    spreading_factor,
                    bandwidth,
                    coding_rate,
                    meta.get("periodicity"),
                    meta.get("burst_ratio"),
                    meta.get("bit_pattern"),
                ],
            )
            if fingerprint_id:
                primary_id = fingerprint_id
                evidence.append("rf_fingerprint")

        confidence = self._score_confidence(
            direct_id=(deveui is not None or devaddr is not None),
            vendor_present=False,
            name_present=False,
            secondary_count=sum(1 for x in [app_eui, spreading_factor, bandwidth, coding_rate] if x is not None),
            fingerprint_only=(deveui is None and devaddr is None and fingerprint_id is not None),
        )

        if primary_id:
            return {
                "primary_id": primary_id,
                "secondary_id": {
                    "devaddr": devaddr,
                    "appeui": app_eui,
                    "spreading_factor": spreading_factor,
                    "bandwidth": bandwidth,
                    "coding_rate": coding_rate,
                },
                "identity_type": "LORA_DEVICE" if (deveui or devaddr) else "LORA_RF_FINGERPRINT",
                "identity_source": "LORA_FRAME" if (deveui or devaddr) else "LORA_RF_PATTERN",
                "confidence": confidence,
                "vendor": None,
                "vendor_oui": None,
                "fingerprint_id": fingerprint_id,
                "evidence": evidence,
                "timestamp": time.time(),
            }

        return self._empty_identity()

    # =========================================================================
    # SUB-GHZ / OOK / FSK
    # =========================================================================
    def _extract_subghz(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        meta = self._meta(signal)
        evidence: List[str] = []

        device_id = self._clean_text(meta.get("device_id"))
        serial_no = self._clean_text(meta.get("serial_no") or meta.get("serial"))
        bit_pattern = self._clean_text(meta.get("bit_pattern"))
        frame_signature = self._clean_text(meta.get("frame_signature"))
        periodicity = meta.get("periodicity")
        burst_ratio = meta.get("burst_ratio")

        if device_id:
            evidence.append("device_id")
        if serial_no:
            evidence.append("serial_no")
        if bit_pattern:
            evidence.append("bit_pattern")
        if frame_signature:
            evidence.append("frame_signature")
        if periodicity is not None:
            evidence.append("periodicity")
        if burst_ratio is not None:
            evidence.append("burst_ratio")

        primary_id = device_id or serial_no
        fingerprint_id = None

        if not primary_id:
            fingerprint_id = self._build_fingerprint_id(
                protocol="SUBGHZ",
                fields=[
                    signal.get("frequency_mhz"),
                    bit_pattern,
                    frame_signature,
                    periodicity,
                    burst_ratio,
                    meta.get("bandwidth_class"),
                    meta.get("signal_type"),
                ],
            )
            if fingerprint_id:
                primary_id = fingerprint_id
                evidence.append("rf_fingerprint")

        confidence = self._score_confidence(
            direct_id=(device_id is not None or serial_no is not None),
            vendor_present=False,
            name_present=False,
            secondary_count=sum(1 for x in [bit_pattern, frame_signature, periodicity, burst_ratio] if x is not None),
            fingerprint_only=(device_id is None and serial_no is None and fingerprint_id is not None),
        )

        if primary_id:
            return {
                "primary_id": primary_id,
                "secondary_id": {
                    "serial_no": serial_no,
                    "pattern": bit_pattern,
                    "frame_signature": frame_signature,
                    "periodicity": periodicity,
                    "burst_ratio": burst_ratio,
                },
                "identity_type": "RF_DEVICE" if (device_id or serial_no) else "RF_FINGERPRINT_DEVICE",
                "identity_source": "RF_PATTERN" if (device_id or serial_no) else "RF_BEHAVIORAL_PATTERN",
                "confidence": confidence,
                "vendor": None,
                "vendor_oui": None,
                "fingerprint_id": fingerprint_id,
                "evidence": evidence,
                "timestamp": time.time(),
            }

        return self._empty_identity()

    # =========================================================================
    # GENERIC RF FALLBACK
    # =========================================================================
    def _extract_generic_rf(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        meta = self._meta(signal)
        fingerprint_id = self._build_fingerprint_id(
            protocol=str(signal.get("protocol") or "UNKNOWN"),
            fields=[
                signal.get("frequency_mhz"),
                signal.get("protocol"),
                meta.get("bandwidth_estimate_mhz"),
                meta.get("signal_type"),
                meta.get("periodicity"),
                meta.get("burst_ratio"),
                meta.get("peak_density"),
                meta.get("spectral_flatness"),
                meta.get("edge_steepness"),
            ],
        )

        if not fingerprint_id:
            return self._empty_identity()

        return {
            "primary_id": fingerprint_id,
            "secondary_id": {
                "protocol": signal.get("protocol"),
                "rf_band": signal.get("rf_band") or meta.get("rf_band"),
            },
            "identity_type": "RF_FINGERPRINT",
            "identity_source": "GENERIC_RF_PATTERN",
            "confidence": 0.35,
            "vendor": None,
            "vendor_oui": None,
            "fingerprint_id": fingerprint_id,
            "evidence": ["rf_fingerprint"],
            "timestamp": time.time(),
        }

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _meta(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        value = signal.get("metadata", {})
        return value if isinstance(value, dict) else {}

    def _empty_identity(self) -> Dict[str, Any]:
        return {
            "primary_id": None,
            "secondary_id": None,
            "identity_type": None,
            "identity_source": None,
            "confidence": 0.0,
            "vendor": None,
            "vendor_oui": None,
            "fingerprint_id": None,
            "evidence": [],
            "timestamp": time.time(),
        }

    def _clean_text(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        lowered = text.lower()
        if lowered in {"unknown", "none", "null", "n/a", "na"}:
            return None
        return text

    def _normalize_uuid(self, value: Any) -> Optional[str]:
        text = self._clean_text(value)
        if not text:
            return None
        text = text.strip("{}").upper()
        if self.UUID_RE.match(text):
            return text
        return None

    def _normalize_hex_id(
        self,
        value: Any,
        expected_lengths: Optional[set[int]] = None,
    ) -> Optional[str]:
        text = self._clean_text(value)
        if not text:
            return None

        text = text.upper().replace("0X", "").replace(":", "").replace("-", "").replace(".", "")
        if not self.HEX_RE.match(text):
            return None

        if expected_lengths and len(text) not in expected_lengths:
            return None

        return text

    def _normalize_mac(self, value: Any) -> Optional[str]:
        text = self._clean_text(value)
        if not text:
            return None

        text = text.upper().replace("-", "").replace(":", "").replace(".", "")
        if not self.MAC_12_RE.match(text):
            return None

        normalized = ":".join(text[i:i + 2] for i in range(0, 12, 2))
        if not self.MAC_17_RE.match(normalized):
            return None

        if normalized == "00:00:00:00:00:00":
            return None

        return normalized

    def _extract_oui(self, mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        return mac[:8]

    def _lookup_vendor_from_mac(self, mac: Optional[str]) -> Optional[str]:
        oui = self._extract_oui(mac)
        if not oui:
            return None
        return self.OUI_MAP.get(oui)

    def _build_fingerprint_id(self, protocol: str, fields: List[Any]) -> Optional[str]:
        normalized: List[str] = []

        for field in fields:
            if field is None:
                continue
            text = str(field).strip()
            if not text:
                continue
            normalized.append(text)

        if len(normalized) < 2:
            return None

        blob = f"{protocol}|{'|'.join(normalized)}"
        digest = hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"RFID-{protocol[:8].upper()}-{digest}"

    def _score_confidence(
        self,
        *,
        direct_id: bool,
        vendor_present: bool,
        name_present: bool,
        secondary_count: int,
        fingerprint_only: bool,
    ) -> float:
        if fingerprint_only and not direct_id:
            base = 0.32
            base += min(0.18, secondary_count * 0.04)
            return round(min(base, 0.55), 4)

        score = 0.40
        if direct_id:
            score += 0.28
        if vendor_present:
            score += 0.12
        if name_present:
            score += 0.08
        score += min(0.12, secondary_count * 0.03)

        return round(min(score, 0.95), 4)

    def _safe_bool(self, value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off"}:
            return False
        return default
