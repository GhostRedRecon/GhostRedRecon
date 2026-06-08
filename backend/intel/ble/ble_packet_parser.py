# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/ble/ble_packet_parser.py
# VERSION:      v4.0.0 (SIGINT PARSER — FULL ADV INTELLIGENCE)
# UPDATED:      2026-03-25
# =============================================================================

import binascii
import string
from typing import Optional, Dict, Any, List

from backend.intel.ble.ble_knowledge_base import BLEKnowledgeBase
from backend.intel.ble.ble_packet_decoder import BLEPacketDecoder


class BLEPacketParser:

    ACCESS_ADDRESS = b"\x8e\x89\xbe\xd6"
    COMPANY_IDS = {
        "004C": "Apple",
        "0006": "Microsoft",
        "00E0": "Google",
        "0059": "Nordic Semiconductor",
        "0075": "Samsung",
        "00E1": "Xiaomi",
        "00C7": "Espressif",
        "0118": "Tile",
        "0133": "Fitbit",
        "00D2": "Bose",
        "00F0": "Garmin",
        "00A0": "Google Nest",
    }
    SERVICE_UUID_NAMES = {
        "180A": "Device Information",
        "180D": "Heart Rate",
        "180F": "Battery Service",
        "1812": "Human Interface Device",
        "181A": "Environmental Sensing",
        "181C": "User Data",
        "181E": "Bond Management",
        "1848": "Generic Media Control",
        "FEAA": "Eddystone",
        "FD6F": "Exposure Notification",
        "FD44": "Apple Continuity",
        "FD5A": "Find My",
        "FD6F": "Exposure Notification",
        "FE2C": "Fast Pair",
        "FE9F": "Google Nearby",
        "FFF0": "Vendor Specific",
    }

    def __init__(self):
        self.decoder = BLEPacketDecoder()
        self.knowledge_base = BLEKnowledgeBase()

    # =========================================================================
    # MAIN PARSER
    # =========================================================================
    def parse(self, bits: List[int], freq: Optional[float] = None) -> List[Dict[str, Any]]:

        results: List[Dict[str, Any]] = []

        try:
            channel = self._freq_to_channel(freq)
            decoded_packets = self.decoder.decode(bits, channel)

            for pkt in decoded_packets:

                mac = pkt.get("mac_address")
                pdu_type = pkt.get("pdu_type_label")
                if mac and not self._is_valid_mac(mac):
                    continue

                raw_payload = pkt.get("advertising_payload") or pkt.get("raw_payload")

                adv_data = self._parse_advertisement_candidates(
                    advertising_payload_hex=raw_payload,
                    raw_pdu_hex=pkt.get("raw_payload"),
                    pdu_type_label=pdu_type,
                )
                signature_match = self.knowledge_base.match_product(pkt, adv_data)
                result = {
                    "mac_address": mac,
                    "raw_payload": pkt.get("raw_payload"),
                    "advertising_payload": pkt.get("advertising_payload"),
                    "parser": "real",
                    "valid": True,
                    "crc_valid": pkt.get("crc_valid", False),
                    "crc": pkt.get("crc"),
                    "computed_crc": pkt.get("computed_crc"),
                    "pdu_type": pkt.get("pdu_type"),
                    "pdu_type_label": pdu_type,
                    "tx_add_randomized": pkt.get("tx_add_randomized"),
                    "rx_add_randomized": pkt.get("rx_add_randomized"),
                    "is_extended_advertising": pkt.get("is_extended_advertising", False),
                    "adv_data": adv_data,
                    "device_name": adv_data.get("device_name"),
                    "manufacturer_id": adv_data.get("manufacturer_id"),
                    "manufacturer_company": adv_data.get("manufacturer_company"),
                    "manufacturer_data": adv_data.get("manufacturer_data"),
                    "service_uuids": adv_data.get("service_uuids"),
                    "service_uuid_names": adv_data.get("service_uuid_names"),
                    "service_data": adv_data.get("service_data"),
                    "tx_power": adv_data.get("tx_power"),
                    "appearance": adv_data.get("appearance"),
                    "flags": adv_data.get("flags"),
                    "shortened_name": adv_data.get("shortened_name"),
                    "complete_name": adv_data.get("complete_name"),
                    "appearance_label": adv_data.get("appearance_label"),
                    "ad_types": adv_data.get("ad_types"),
                    "ad_structure_count": adv_data.get("ad_structure_count"),
                    "contains_scan_response_data": pdu_type == "SCAN_RSP",
                    "signature_match": signature_match,
                }

                results.append(result)

        except Exception:
            pass

        # ---------------------------------------------------------
        # FALLBACK (unchanged)
        # ---------------------------------------------------------
        if not results:
            fallback = self._fallback_parse(bits)
            if fallback:
                results.append(fallback)

        return results

    # =========================================================================
    # 🔥 NEW: BLE ADVERTISEMENT PARSER
    # =========================================================================
    def _empty_adv(self) -> Dict[str, Any]:
        return {
            "device_name": None,
            "shortened_name": None,
            "complete_name": None,
            "broadcast_name": None,
            "broadcast_code": None,
            "manufacturer_id": None,
            "manufacturer_company": None,
            "manufacturer_data": None,
            "service_uuids": [],
            "service_uuid_names": [],
            "service_data": {},
            "tx_power": None,
            "appearance": None,
            "appearance_label": None,
            "flags": None,
            "ad_types": [],
            "ad_structure_count": 0,
            "malformed_ad_structure_count": 0,
            "parse_warnings": [],
        }

    def _parse_advertisement(self, payload_hex: Optional[str]) -> Dict[str, Any]:

        adv = self._empty_adv()

        if not payload_hex:
            return adv

        try:
            payload = bytes.fromhex(payload_hex)
        except Exception:
            return adv

        return self._parse_advertisement_bytes(payload)

    def _is_plausible_manufacturer_block(self, company_id: str, payload_hex: str, company_name: Optional[str]) -> bool:
        if not company_id or len(company_id) != 4:
            return False
        normalized_company = company_id.upper()
        payload = (payload_hex or "").upper()
        if payload and len(payload) < 2:
            return False
        if normalized_company in {"0000", "FFFF", "FF00", "00FF"}:
            return False
        if payload and set(payload) == {"0"}:
            return False
        if payload and set(payload) == {"F"}:
            return False
        if company_name:
            return True
        return len(payload) >= 6

    def _is_printable_name(self, decoded_name: str) -> bool:
        if not decoded_name or len(decoded_name.strip()) < 2:
            return False
        printable = set(string.printable) - set("\r\n\t\x0b\x0c")
        return all(ch in printable for ch in decoded_name)

    def _parse_advertisement_candidates(
        self,
        advertising_payload_hex: Optional[str],
        raw_pdu_hex: Optional[str],
        pdu_type_label: Optional[str],
    ) -> Dict[str, Any]:
        candidates: List[bytes] = []

        for payload_hex in (advertising_payload_hex, raw_pdu_hex):
            if not payload_hex:
                continue
            try:
                payload = bytes.fromhex(payload_hex)
            except Exception:
                continue
            if payload:
                candidates.append(payload)

        if raw_pdu_hex:
            try:
                raw_pdu = bytes.fromhex(raw_pdu_hex)
            except Exception:
                raw_pdu = b""
            if raw_pdu:
                if pdu_type_label in {"ADV_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND", "SCAN_RSP"} and len(raw_pdu) > 6:
                    candidates.append(raw_pdu[6:])
                if pdu_type_label in {"ADV_DIRECT_IND", "SCAN_REQ", "CONNECT_IND"} and len(raw_pdu) > 12:
                    candidates.append(raw_pdu[12:])

        best = self._empty_adv()
        best_score = -1
        seen_payloads = set()
        for payload in candidates:
            for offset in range(0, min(4, len(payload))):
                candidate = payload[offset:]
                if not candidate:
                    continue
                key = candidate[:32]
                if key in seen_payloads:
                    continue
                seen_payloads.add(key)
                parsed = self._parse_advertisement_bytes(candidate)
                score = self._adv_score(parsed)
                if score > best_score:
                    best = parsed
                    best_score = score
        return best

    def _parse_advertisement_bytes(self, payload: bytes) -> Dict[str, Any]:
        adv = self._empty_adv()
        if not payload:
            return adv

        i = 0

        try:
            while i < len(payload):
                remaining = len(payload) - i
                if remaining < 2:
                    break
                length = payload[i]

                if length == 0:
                    break

                if length >= remaining:
                    adv["malformed_ad_structure_count"] += 1
                    adv["parse_warnings"].append("truncated_ad_structure")
                    break

                ad_type = payload[i + 1]
                data = payload[i + 2:i + 1 + length]
                adv["ad_types"].append(f"0x{ad_type:02X}")
                adv["ad_structure_count"] += 1

                # -------------------------------------------------
                # DEVICE NAME
                # -------------------------------------------------
                if ad_type in (0x08, 0x09):
                    try:
                        decoded_name = data.decode(errors="ignore")
                        if self._is_printable_name(decoded_name):
                            adv["device_name"] = decoded_name
                            if ad_type == 0x08:
                                adv["shortened_name"] = decoded_name
                            else:
                                adv["complete_name"] = decoded_name
                    except Exception:
                        pass

                # -------------------------------------------------
                # MANUFACTURER DATA
                # -------------------------------------------------
                elif ad_type == 0xFF:
                    if len(data) >= 2:
                        company_id = data[:2].hex().upper()
                        manufacturer_payload = data[2:].hex().upper() if len(data) > 2 else ""
                        company_name = (
                            self.knowledge_base.company_name(company_id)
                            or self.COMPANY_IDS.get(company_id)
                        )
                        if self._is_plausible_manufacturer_block(company_id, manufacturer_payload, company_name):
                            adv["manufacturer_id"] = company_id
                            adv["manufacturer_company"] = company_name
                            adv["manufacturer_data"] = manufacturer_payload

                # -------------------------------------------------
                # SERVICE UUIDS (16-bit)
                # -------------------------------------------------
                elif ad_type in (0x02, 0x03):
                    if len(data) % 2 != 0:
                        adv["malformed_ad_structure_count"] += 1
                        adv["parse_warnings"].append("misaligned_16bit_uuid_block")
                        i += length + 1
                        continue
                    for j in range(0, len(data), 2):
                        uuid = data[j:j + 2][::-1].hex().upper()
                        adv["service_uuids"].append(uuid)
                elif ad_type in (0x06, 0x07):
                    if len(data) % 16 != 0:
                        adv["malformed_ad_structure_count"] += 1
                        adv["parse_warnings"].append("misaligned_128bit_uuid_block")
                        i += length + 1
                        continue
                    for j in range(0, len(data), 16):
                        uuid = data[j:j + 16].hex().upper()
                        if uuid:
                            adv["service_uuids"].append(uuid)
                elif ad_type == 0x16 and len(data) >= 2:
                    service_uuid = data[:2][::-1].hex().upper()
                    adv["service_data"][service_uuid] = data[2:].hex().upper()
                    adv["service_uuids"].append(service_uuid)
                elif ad_type == 0x20 and len(data) >= 4:
                    if len(data) < 8:
                        adv["malformed_ad_structure_count"] += 1
                        adv["parse_warnings"].append("short_32bit_service_data")
                        i += length + 1
                        continue
                    service_uuid = data[:4][::-1].hex().upper()
                    adv["service_data"][service_uuid] = data[4:].hex().upper()
                    adv["service_uuids"].append(service_uuid)
                elif ad_type == 0x21 and len(data) >= 16:
                    if len(data) < 18:
                        adv["malformed_ad_structure_count"] += 1
                        adv["parse_warnings"].append("short_128bit_service_data")
                        i += length + 1
                        continue
                    service_uuid = data[:16].hex().upper()
                    adv["service_data"][service_uuid] = data[16:].hex().upper()
                    adv["service_uuids"].append(service_uuid)
                elif ad_type == 0x19 and len(data) >= 2:
                    adv["appearance"] = int.from_bytes(data[:2], "little")
                    adv["appearance_label"] = self._appearance_name(adv["appearance"])
                elif ad_type == 0x01 and len(data) >= 1:
                    adv["flags"] = data[0]
                elif ad_type == 0x30 and data:
                    decoded_name = data.decode(errors="ignore")
                    if self._is_printable_name(decoded_name):
                        adv["broadcast_name"] = decoded_name
                elif ad_type == 0x31 and data:
                    adv["broadcast_code"] = data.hex().upper()

                # -------------------------------------------------
                # TX POWER
                # -------------------------------------------------
                elif ad_type == 0x0A:
                    if len(data) == 1:
                        adv["tx_power"] = int.from_bytes(data, "little", signed=True)

                i += length + 1

        except Exception:
            pass

        if not adv.get("device_name"):
            adv["device_name"] = adv.get("complete_name") or adv.get("shortened_name") or adv.get("broadcast_name")
        adv["service_uuids"] = list(dict.fromkeys(adv["service_uuids"]))
        adv["service_uuid_names"] = [
            self.knowledge_base.service_name(uuid) or self.SERVICE_UUID_NAMES.get(uuid, uuid)
            for uuid in adv["service_uuids"]
        ]
        if adv.get("malformed_ad_structure_count"):
            adv["service_uuids"] = []
            adv["service_uuid_names"] = []
            adv["service_data"] = {}
            if not adv.get("manufacturer_company"):
                adv["manufacturer_id"] = None
                adv["manufacturer_data"] = None

        return adv

    def _adv_score(self, adv: Dict[str, Any]) -> int:
        score = 0
        score += int(adv.get("ad_structure_count") or 0) * 2
        if adv.get("manufacturer_id"):
            score += 8
        if adv.get("manufacturer_company"):
            score += 6
        if adv.get("device_name"):
            score += 6
        if adv.get("broadcast_name"):
            score += 4
        if adv.get("service_uuids"):
            score += 4
        if adv.get("service_data"):
            score += 4
        if adv.get("manufacturer_data"):
            score += 3
        if adv.get("appearance") is not None:
            score += 2
        return score

    def _appearance_name(self, appearance: Optional[int]) -> Optional[str]:
        if appearance is None:
            return None
        mapping = {
            64: "Phone",
            128: "Computer",
            192: "Watch",
            193: "Watch: Sports",
            512: "Tag",
            576: "Eye Glasses",
            832: "Heart Rate Sensor",
            960: "Keyring",
        }
        return mapping.get(int(appearance))

    # =========================================================================
    # FALLBACK PARSER (UNCHANGED)
    # =========================================================================
    def _fallback_parse(self, bits: List[int]) -> Optional[Dict[str, Any]]:

        try:
            data = self._bits_to_bytes(bits)

            for i in range(len(data) - 50):

                chunk = data[i:i + 50]

                if self.ACCESS_ADDRESS in chunk:

                    mac = self._extract_mac(chunk)

                    if self._is_valid_mac(mac):
                        return {
                            "mac_address": mac,
                            "raw_payload": chunk.hex(),
                            "parser": "fallback",
                            "valid": False,
                        }

        except Exception:
            pass

        return None

    # =========================================================================
    # MAC VALIDATION (UNCHANGED)
    # =========================================================================
    def _is_valid_mac(self, mac: Optional[str]) -> bool:

        if not mac:
            return False

        if len(mac.split(":")) != 6:
            return False

        if mac == "00:00:00:00:00:00":
            return False

        if mac.startswith("FF:FF:FF"):
            return False

        return True

    # =========================================================================
    # LEGACY SUPPORT (UNCHANGED)
    # =========================================================================
    def parse_file(self, path="/tmp/ble_bits.bin"):

        devices = []

        try:
            with open(path, "rb") as f:
                data = f.read()

            for i in range(0, len(data) - 50):

                chunk = data[i:i + 50]

                if self.ACCESS_ADDRESS in chunk:

                    mac = self._extract_mac(chunk)

                    if self._is_valid_mac(mac):
                        devices.append({
                            "mac_address": mac,
                            "type": "ble_advertisement"
                        })

        except Exception:
            pass

        return devices

    # =========================================================================
    # MAC EXTRACTION (UNCHANGED)
    # =========================================================================
    def _extract_mac(self, payload):

        try:
            mac_bytes = payload[10:16]
            return ":".join(f"{b:02X}" for b in mac_bytes)
        except Exception:
            return None

    # =========================================================================
    # BIT → BYTE (UNCHANGED)
    # =========================================================================
    def _bits_to_bytes(self, bits: List[int]) -> bytes:

        out = []

        limit = len(bits) - (len(bits) % 8)

        for i in range(0, limit, 8):
            byte = 0
            for j in range(8):
                byte |= (bits[i + j] << j)
            out.append(byte)

        return bytes(out)

    # =========================================================================
    # FREQ → CHANNEL (UNCHANGED)
    # =========================================================================
    def _freq_to_channel(self, freq: Optional[float]) -> int:

        if not freq:
            return 37

        mhz = freq / 1e6

        if abs(mhz - 2402) < 2:
            return 37
        elif abs(mhz - 2426) < 2:
            return 38
        elif abs(mhz - 2480) < 2:
            return 39

        return 37
