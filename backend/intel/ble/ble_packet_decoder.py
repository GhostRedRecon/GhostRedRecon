# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/ble/ble_packet_decoder.py
# VERSION:      v3.0.0 (SIGINT BLE DECODER — CRC-AWARE QUALITY GATE)
# UPDATED:      2026-04-02
# =============================================================================

import os
from typing import List, Dict, Optional


class BLEPacketDecoder:
    """
    SIGINT BLE Packet Decoder

    PURPOSE:
    --------
    Convert raw bitstream → valid BLE packets

    CAPABILITIES:
    -------------
    - Bit alignment scanning (0–7 shift)
    - Access address detection (0x8E89BED6)
    - De-whitening (BLE spec compliant)
    - Multi-packet extraction
    - MAC address extraction
    - Robust against noisy SDR input

    DESIGN PRINCIPLES:
    ------------------
    - Tolerant to bit misalignment
    - Stateless decoding
    - Safe parsing (no crashes)
    - Multi-packet support (SIGINT requirement)

    NOTES:
    ------
    - BLE advertising uses fixed access address: 0x8E89BED6
    - Whitening depends on channel (37/38/39)
    - MAC is little-endian in packet
    """

    ACCESS_ADDRESS = 0x8E89BED6
    ACCESS_ADDRESS_MASK = int((os.getenv("GHOSTRECON_BLE_ACCESS_MASK") or "FFFFFFFF").strip(), 16)
    MAX_ACCESS_BIT_ERRORS = max(0, int((os.getenv("GHOSTRECON_BLE_ACCESS_MAX_ERRORS") or "3").strip()))
    ADV_CRC_INIT = 0x555555
    ADV_CRC_POLY = 0x00065B
    PDU_TYPE_LABELS = {
        0x0: "ADV_IND",
        0x1: "ADV_DIRECT_IND",
        0x2: "ADV_NONCONN_IND",
        0x3: "SCAN_REQ",
        0x4: "SCAN_RSP",
        0x5: "CONNECT_IND",
        0x6: "ADV_SCAN_IND",
        0x7: "ADV_EXT_IND",
    }

    # =========================================================================
    # ENTRY POINT
    # =========================================================================
    def decode(self, bits: List[int], channel: int) -> List[Dict]:

        packets = []
        seen = set()

        if not bits or len(bits) < 80:
            return packets

        for shift in range(8):
            aligned_bits = bits[shift:]
            for bit_order in ("lsb", "msb"):
                data = self._bits_to_bytes(aligned_bits, bit_order=bit_order)

                for i in range(len(data) - 40):
                    try:
                        access_bytes = data[i:i + 4]
                        if len(access_bytes) < 4:
                            continue

                        access_word = int.from_bytes(access_bytes, byteorder="little")
                        access_errors = self._access_address_errors(access_word)
                        if access_errors > self.MAX_ACCESS_BIT_ERRORS:
                            continue

                        packet = data[i:]
                        decoded = self._process_packet(packet, channel)

                        if decoded:
                            decoded["bit_shift"] = shift
                            decoded["bit_order"] = bit_order
                            decoded["access_address_errors"] = access_errors
                            key = (
                                decoded.get("mac_address"),
                                decoded.get("raw_payload"),
                                decoded.get("pdu_type"),
                                decoded.get("crc"),
                            )
                            if key in seen:
                                continue
                            seen.add(key)
                            packets.append(decoded)
                    except Exception:
                        continue

        return packets

    # =========================================================================
    # PROCESS PACKET
    # =========================================================================
    def _process_packet(self, packet: bytes, channel: int) -> Optional[Dict]:

        try:
            if len(packet) < 10:
                return None

            # Remove access address
            payload = packet[4:]
            best_candidate = None
            best_score = -1

            for whitening_mode, dewhitened in self._candidate_dewhitenings(payload, channel):
                candidate = self._parse_dewhitened_packet(dewhitened, whitening_mode)
                if not candidate:
                    continue
                score = self._packet_quality_score(candidate)
                if score > best_score:
                    best_candidate = candidate
                    best_score = score

            return best_candidate

        except Exception:
            return None

    def _parse_dewhitened_packet(self, dewhitened: bytes, whitening_mode: str) -> Optional[Dict]:
        if len(dewhitened) < 4:
            return None

        header = dewhitened[0:2]
        header0 = header[0]
        length = header[1] & 0b00111111

        if length <= 0 or length > 37:
            return None

        pdu_type = header0 & 0x0F
        if pdu_type > 0x07:
            return None
        pdu_label = self.PDU_TYPE_LABELS.get(pdu_type, f"PDU_{pdu_type}")
        tx_add = bool(header0 & 0b01000000)
        rx_add = bool(header0 & 0b10000000)

        if len(dewhitened) < 2 + length + 3:
            return None

        pdu = dewhitened[2:2 + length]
        crc_bytes = dewhitened[2 + length:2 + length + 3]

        if len(pdu) < 2:
            return None

        if pdu_type in {0x0, 0x1, 0x2, 0x4, 0x6} and len(pdu) < 6:
            return None
        if pdu_type in {0x3, 0x5} and len(pdu) < 12:
            return None

        ad_payload = b""
        mac = self._extract_mac_from_pdu(pdu, pdu_type)
        if pdu_type in {0x0, 0x2, 0x4, 0x6} and len(pdu) >= 6:
            ad_payload = pdu[6:]
        elif pdu_type == 0x7:
            mac, ad_payload = self._extract_extended_adv_fields(pdu, mac)

        computed_crc = self._compute_crc(header + pdu)
        computed_crc_bytes = computed_crc.to_bytes(3, byteorder="little", signed=False)
        crc_valid = crc_bytes == computed_crc_bytes

        return {
            "mac_address": mac,
            "raw_payload": pdu.hex(),
            "length": length,
            "pdu_type": pdu_type,
            "pdu_type_label": pdu_label,
            "tx_add_randomized": tx_add,
            "rx_add_randomized": rx_add,
            "advertising_payload": ad_payload.hex() if ad_payload else "",
            "is_extended_advertising": pdu_type == 0x7,
            "crc_valid": crc_valid,
            "crc": crc_bytes.hex().upper(),
            "computed_crc": computed_crc_bytes.hex().upper(),
            "whitening_mode": whitening_mode,
        }

    def _packet_quality_score(self, packet: Dict) -> int:
        score = 0
        if packet.get("crc_valid"):
            score += 100
        access_errors = int(packet.get("access_address_errors") or 0)
        score += max(0, 24 - (access_errors * 6))
        score += min(20, int(packet.get("length") or 0))
        pdu_type = packet.get("pdu_type_label")
        if pdu_type in {"ADV_IND", "ADV_NONCONN_IND", "SCAN_RSP", "ADV_SCAN_IND", "ADV_EXT_IND"}:
            score += 10
        mac = packet.get("mac_address") or ""
        octets = [part for part in mac.split(":") if part]
        if len(set(octets)) >= 4:
            score += 8
        return score

    def _candidate_dewhitenings(self, data: bytes, channel: int) -> List[tuple[str, bytes]]:
        return [
            ("lsb", self._dewhiten_lsb(data, channel)),
            ("msb", self._dewhiten_msb(data, channel)),
        ]

    def _extract_mac_from_pdu(self, pdu: bytes, pdu_type: int) -> Optional[str]:
        if pdu_type in {0x0, 0x1, 0x2, 0x4, 0x6} and len(pdu) >= 6:
            mac_bytes = pdu[0:6]
        elif pdu_type in {0x3, 0x5} and len(pdu) >= 12:
            mac_bytes = pdu[6:12]
        else:
            return None
        return ":".join(f"{b:02X}" for b in mac_bytes[::-1])

    def _extract_extended_adv_fields(self, pdu: bytes, fallback_mac: Optional[str]) -> tuple[Optional[str], bytes]:
        if len(pdu) < 2:
            return fallback_mac, b""
        ext_header_len = pdu[0] & 0x3F
        ext_header_start = 1
        ext_header_end = min(len(pdu), ext_header_start + ext_header_len)
        ext_header = pdu[ext_header_start:ext_header_end]
        adv_data = pdu[ext_header_end:]
        mac = fallback_mac
        if ext_header:
            flags = ext_header[0]
            offset = 1
            if flags & 0x01 and len(ext_header) >= offset + 6:
                mac_bytes = ext_header[offset:offset + 6]
                mac = ":".join(f"{b:02X}" for b in mac_bytes[::-1])
        return mac, adv_data

    # =========================================================================
    # DE-WHITENING (BLE SPEC)
    # =========================================================================
    def _dewhiten_lsb(self, data: bytes, channel: int) -> bytes:

        # BLE whitening init = channel | 0x40
        lfsr = (channel & 0x3F) | 0x40

        output = []

        for byte in data:
            new_byte = 0

            for i in range(8):
                bit = (byte >> i) & 1
                whitening_bit = lfsr & 1

                new_bit = bit ^ whitening_bit
                new_byte |= (new_bit << i)

                # LFSR update (x^7 + x^4 + 1)
                feedback = ((lfsr >> 6) ^ (lfsr >> 3)) & 1
                lfsr = ((lfsr >> 1) | (feedback << 6)) & 0x7F

            output.append(new_byte)

        return bytes(output)

    def _dewhiten_msb(self, data: bytes, channel: int) -> bytes:
        lfsr = (channel & 0x3F) | 0x40
        output = []

        for byte in data:
            new_byte = 0
            for i in range(8):
                bit = (byte >> i) & 1
                whitening_bit = (lfsr >> 6) & 1
                new_bit = bit ^ whitening_bit
                new_byte |= (new_bit << i)
                feedback = ((lfsr >> 6) ^ (lfsr >> 3)) & 1
                lfsr = ((lfsr << 1) & 0x7E) | feedback
            output.append(new_byte)

        return bytes(output)

    def _compute_crc(self, payload: bytes) -> int:
        state = self.ADV_CRC_INIT
        for byte in payload:
            current = byte
            for _ in range(8):
                bit = (state & 0x01) ^ (current & 0x01)
                state >>= 1
                if bit:
                    state ^= self.ADV_CRC_POLY
                current >>= 1
        return state & 0xFFFFFF

    # =========================================================================
    # BIT → BYTE
    # =========================================================================
    def _bits_to_bytes(self, bits: List[int], bit_order: str = "lsb") -> bytes:

        out = []

        # ensure multiple of 8
        limit = len(bits) - (len(bits) % 8)

        for i in range(0, limit, 8):
            byte = 0
            for j in range(8):
                bit = bits[i + j] & 1
                if bit_order == "msb":
                    byte |= (bit << (7 - j))
                else:
                    byte |= (bit << j)
            out.append(byte)

        return bytes(out)

    def _access_address_errors(self, observed_word: int) -> int:
        masked_expected = self.ACCESS_ADDRESS & self.ACCESS_ADDRESS_MASK
        masked_observed = observed_word & self.ACCESS_ADDRESS_MASK
        diff = masked_expected ^ masked_observed
        return diff.bit_count()
