# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/zigbee/zigbee_ieee802154_decoder.py
# VERSION:      v3.0.0 (PRODUCTION IEEE 802.15.4 DECODER)
# UPDATED:      2026-03-25
# =============================================================================

from backend.intel.zigbee.zigbee_dsss_despreader import ZigbeeDSSSDespreader


class ZigbeeIEEE802154Decoder:
    """
    Full IEEE 802.15.4 Frame Decoder

    Responsibilities:
    - DSSS despreading
    - frame extraction
    - FCS validation
    - MAC frame parsing
    - address mode handling
    - PAN compression awareness
    - role inference

    Design notes:
    - Keeps strict FCS validation by default
    - Preserves prior behavior and field names
    - Adds safer parsing and better debug support
    """

    PREAMBLE_SFD = [0x00, 0x00, 0x00, 0x00, 0xA7]

    def __init__(self, strict_fcs=True, debug=False):
        self.dsss = ZigbeeDSSSDespreader()
        self.strict_fcs = strict_fcs
        self.debug = debug

    # =========================================================================
    # PUBLIC ENTRY
    # =========================================================================
    def decode(self, chip_stream):
        """
        Decode chip stream into parsed IEEE 802.15.4 frames.

        Input:
            chip_stream: iterable of soft or hard chip values

        Output:
            list[dict]
        """

        if chip_stream is None:
            return []

        symbols = self.dsss.despread(chip_stream)
        if len(symbols) < 10:
            if self.debug:
                print("[ZIGBEE DECODER] Not enough despread symbols")
            return []

        byte_stream = self.dsss.symbols_to_bytes(symbols)

        if self.debug:
            print(f"[ZIGBEE DECODER] Symbols: {len(symbols)} | Bytes: {len(byte_stream)}")

        return self._extract_frames(byte_stream)

    # =========================================================================
    # FRAME EXTRACTION
    # =========================================================================
    def _extract_frames(self, data):
        """
        Extract candidate frames from byte stream using preamble/SFD + length.
        """

        frames = []

        if not data or len(data) < 10:
            return frames

        i = 0
        while i < len(data) - 10:

            # IEEE 802.15.4 preamble + SFD
            if data[i:i + 5] == self.PREAMBLE_SFD:

                if i + 5 >= len(data):
                    break

                length = data[i + 5]

                # PHY length sanity
                if length < 5 or length > 127:
                    if self.debug:
                        print(f"[ZIGBEE DECODER] Invalid length {length} at offset {i}")
                    i += 1
                    continue

                frame_start = i + 6
                frame_end = frame_start + length
                frame = data[frame_start:frame_end]

                if len(frame) < length:
                    if self.debug:
                        print("[ZIGBEE DECODER] Truncated frame at end of stream")
                    break

                # Strict mode: require valid FCS
                if self.strict_fcs:
                    if self._validate_fcs(frame):
                        parsed = self._parse_frame(frame)
                        if parsed:
                            parsed["phy_length"] = length
                            parsed["fcs_valid"] = True
                            frames.append(parsed)
                    else:
                        if self.debug:
                            print(f"[ZIGBEE DECODER] FCS failed at offset {i}")
                else:
                    # Best-effort mode
                    parsed = self._parse_frame(frame)
                    if parsed:
                        parsed["phy_length"] = length
                        parsed["fcs_valid"] = self._validate_fcs(frame)
                        frames.append(parsed)

                i += length + 6
            else:
                i += 1

        if self.debug:
            print(f"[ZIGBEE DECODER] Extracted frames: {len(frames)}")

        return frames

    # =========================================================================
    # FCS / CRC
    # =========================================================================
    def _validate_fcs(self, frame):
        """
        Validate 802.15.4 16-bit FCS.

        Frame format expected here:
            [MAC header + MAC payload + FCS(2 bytes)]
        """

        if len(frame) < 3:
            return False

        data = frame[:-2]
        received_fcs = list(frame[-2:])
        calc = self._crc16(data)

        return received_fcs == calc

    def _crc16(self, data):
        """
        CRC-16/CCITT-style implementation as previously used in this project.

        Returns:
            [low_byte, high_byte]
        """

        crc = 0x0000

        for byte in data:
            crc ^= byte << 8

            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1

                crc &= 0xFFFF

        return [crc & 0xFF, (crc >> 8) & 0xFF]

    # =========================================================================
    # FRAME PARSING
    # =========================================================================
    def _parse_frame(self, frame):
        """
        Parse an IEEE 802.15.4 MAC frame.

        Preserves prior output fields:
            - type
            - frame_type
            - seq
            - dest_pan
            - dest_addr
            - src_addr
            - role
            - confidence
        """

        if len(frame) < 5:
            return None

        try:
            fcf = frame[0] | (frame[1] << 8)
            frame_type = fcf & 0x0007
            security_enabled = (fcf >> 3) & 0x1
            frame_pending = (fcf >> 4) & 0x1
            ack_request = (fcf >> 5) & 0x1
            pan_compression = (fcf >> 6) & 0x1
            dest_mode = (fcf >> 10) & 0x3
            frame_version = (fcf >> 12) & 0x3
            src_mode = (fcf >> 14) & 0x3

            seq = frame[2]
            index = 3

            dest_pan = None
            dest_addr = None
            src_pan = None
            src_addr = None

            # -----------------------------------------------------
            # Destination addressing
            # -----------------------------------------------------
            if dest_mode:
                dest_pan, index = self._read_pan(frame, index)
                if dest_pan is None:
                    return None

                dest_addr, index = self._read_addr(frame, index, dest_mode)
                if dest_mode and dest_addr is None:
                    return None

            # -----------------------------------------------------
            # Source PAN / source address
            # PAN compression means source PAN is omitted and equals dest PAN
            # -----------------------------------------------------
            if src_mode:
                if pan_compression and dest_pan is not None:
                    src_pan = dest_pan
                else:
                    src_pan, index = self._read_pan(frame, index)
                    if src_pan is None:
                        return None

                src_addr, index = self._read_addr(frame, index, src_mode)
                if src_addr is None:
                    return None

            role = self._infer_role(frame_type, src_mode)

            parsed = {
                "type": "zigbee_frame",
                "frame_type": frame_type,
                "seq": seq,
                "dest_pan": dest_pan,
                "dest_addr": dest_addr,
                "src_addr": src_addr,
                "role": role,
                "confidence": 0.9,

                # Added metadata (non-breaking)
                "src_pan": src_pan,
                "fcf": fcf,
                "security_enabled": bool(security_enabled),
                "frame_pending": bool(frame_pending),
                "ack_request": bool(ack_request),
                "pan_compression": bool(pan_compression),
                "dest_mode": dest_mode,
                "src_mode": src_mode,
                "frame_version": frame_version,
            }

            if self.debug:
                print(f"[ZIGBEE DECODER] Parsed frame: {parsed}")

            return parsed

        except Exception as e:
            if self.debug:
                print(f"[ZIGBEE DECODER] Parse error: {e}")
            return None

    # =========================================================================
    # LOW-LEVEL READ HELPERS
    # =========================================================================
    def _read_pan(self, frame, index):
        if index + 1 >= len(frame):
            return None, index
        pan = frame[index] | (frame[index + 1] << 8)
        return pan, index + 2

    def _read_addr(self, frame, index, mode):
        """
        Address modes:
            0 = none
            2 = short (16-bit)
            3 = extended (64-bit)
        """

        if mode == 0:
            return None, index

        if mode == 2:
            if index + 1 >= len(frame):
                return None, index
            addr = frame[index] | (frame[index + 1] << 8)
            return addr, index + 2

        if mode == 3:
            if index + 7 >= len(frame):
                return None, index
            addr = int.from_bytes(frame[index:index + 8], "little")
            return addr, index + 8

        return None, index

    # =========================================================================
    # ROLE INFERENCE
    # =========================================================================
    def _infer_role(self, frame_type, src_mode):
        """
        Preserve prior behavior while keeping logic explicit.
        """

        if frame_type == 0:
            return "beacon"         # coordinator-ish behavior
        elif frame_type == 1:
            return "data_device"
        elif frame_type == 2:
            return "ack"
        elif frame_type == 3:
            return "mac_command"

        return "unknown"
