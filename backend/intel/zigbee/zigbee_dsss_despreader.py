# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/zigbee/zigbee_dsss_despreader.py
# VERSION:      v2.0.0 (SLIDING SYNC + FCS SCORING)
# =============================================================================

import numpy as np


class ZigbeeDSSSDespreader:
    """
    Advanced DSSS Despreader with:
    - Sliding chip alignment
    - Correlation scoring
    - FCS-based validation scoring
    """

    CHIP_TABLE = {
        0x0: "11011001110000110101001000101110",
        0x1: "11101101100111000011010100100010",
        0x2: "00101110110110011100001101010010",
        0x3: "00100010111011011001110000110101",
        0x4: "01010010001011101101100111000011",
        0x5: "00110101001000101110110110011100",
        0x6: "00001101010010001011101101100111",
        0x7: "01110000110101001000101110110110",
        0x8: "01100111000011010100100010111011",
        0x9: "10110110011100001101010010001011",
        0xA: "10111011011001110000110101001000",
        0xB: "00101110110110011100001101010010",
        0xC: "01001000101110110110011100001101",
        0xD: "00110101001000101110110110011100",
        0xE: "00001101010010001011101101100111",
        0xF: "01110000110101001000101110110110",
    }

    def __init__(self):

        self.sequences = {}
        for sym, chips in self.CHIP_TABLE.items():
            self.sequences[sym] = np.array(
                [1 if c == "1" else -1 for c in chips]
            )

    # =========================================================================
    def _correlate(self, window):

        best_sym = None
        best_score = -999

        for sym, seq in self.sequences.items():
            score = np.dot(window, seq)

            if score > best_score:
                best_score = score
                best_sym = sym

        return best_sym, best_score

    # =========================================================================
    def _despread_with_offset(self, chips, offset):

        symbols = []
        total_score = 0

        for i in range(offset, len(chips) - 32, 32):

            window = chips[i:i + 32]

            if len(window) < 32:
                break

            sym, score = self._correlate(window)

            # Reject weak matches
            if score < 8:
                continue

            symbols.append(sym)
            total_score += score

        return symbols, total_score

    # =========================================================================
    def _symbols_to_bytes(self, symbols):

        out = []

        for i in range(0, len(symbols), 2):
            if i + 1 >= len(symbols):
                break

            byte = (symbols[i] << 4) | symbols[i + 1]
            out.append(byte)

        return out

    # =========================================================================
    def _estimate_fcs_hits(self, byte_stream):

        """
        Rough scoring: count valid preamble patterns
        (acts as proxy for real frame detection)
        """

        hits = 0

        for i in range(len(byte_stream) - 5):
            if byte_stream[i:i+5] == [0x00, 0x00, 0x00, 0x00, 0xA7]:
                hits += 1

        return hits

    # =========================================================================
    def despread(self, chip_stream):

        if len(chip_stream) < 64:
            return []

        chips = np.array([1 if c > 0 else -1 for c in chip_stream])

        best_symbols = []
        best_score = -999

        # 🔥 SLIDING ALIGNMENT
        for offset in range(32):

            symbols, corr_score = self._despread_with_offset(chips, offset)

            if len(symbols) < 10:
                continue

            byte_stream = self._symbols_to_bytes(symbols)

            fcs_hits = self._estimate_fcs_hits(byte_stream)

            # 🔥 FINAL SCORE (weighted)
            score = corr_score + (fcs_hits * 200)

            if score > best_score:
                best_score = score
                best_symbols = symbols

        return best_symbols

    # =========================================================================
    def symbols_to_bytes(self, symbols):

        return self._symbols_to_bytes(symbols)
