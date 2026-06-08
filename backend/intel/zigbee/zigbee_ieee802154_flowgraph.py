# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         zigbee_ieee802154_flowgraph.py
# VERSION:      v3.1.0 (PRODUCTION - IMPORT FIX + STABILITY)
# UPDATED:      2026-03-25
# =============================================================================

from gnuradio import gr, blocks
from gnuradio import filter as gr_filter
from gnuradio.filter import firdes
import osmosdr
import numpy as np


class ZigbeeIEEE802154Flowgraph(gr.top_block):
    """
    Zigbee IEEE 802.15.4 GNU Radio Flowgraph

    Responsibilities:
    - SDR capture (HackRF)
    - Baseband filtering
    - Frequency translation (fixed API)
    - IQ → real conversion
    - Provide chip stream to decoder

    Design Principles:
    - Stable SDR lifecycle (no device lock)
    - Clean buffer access
    - Minimal DSP (delegated to PHY/decoder)
    """

    def __init__(self, freq=2405e6, samp_rate=4e6, gain=50):

        super().__init__("Zigbee Flowgraph")

        self.freq = freq
        self.samp_rate = samp_rate
        self.gain = gain

        # ---------------------------------------------------------
        # SDR SOURCE (HackRF)
        # ---------------------------------------------------------
        self.source = osmosdr.source(args="hackrf=0")

        self.source.set_sample_rate(self.samp_rate)
        self.source.set_center_freq(self.freq)
        self.source.set_gain(self.gain)
        self.source.set_if_gain(20)
        self.source.set_bb_gain(20)

        # ---------------------------------------------------------
        # FILTER DESIGN (Zigbee ~2MHz BW)
        # ---------------------------------------------------------
        self.lpf_taps = firdes.low_pass(
            gain=1.0,
            sampling_freq=self.samp_rate,
            cutoff_freq=2e6,
            transition_width=500e3,
            window=firdes.WIN_HAMMING
        )

        # ---------------------------------------------------------
        # FIXED: freq_xlating_fir_filter_ccf (correct module)
        # ---------------------------------------------------------
        self.freq_xlating = gr_filter.freq_xlating_fir_filter_ccf(
            decimation=1,
            taps=self.lpf_taps,
            center_freq=0,
            sampling_freq=self.samp_rate
        )

        # ---------------------------------------------------------
        # IQ → REAL
        # ---------------------------------------------------------
        self.complex_to_real = blocks.complex_to_real()

        # ---------------------------------------------------------
        # BUFFER SINK
        # ---------------------------------------------------------
        self.vector_sink = blocks.vector_sink_f()

        # ---------------------------------------------------------
        # CONNECT GRAPH
        # ---------------------------------------------------------
        self.connect(self.source, self.freq_xlating)
        self.connect(self.freq_xlating, self.complex_to_real)
        self.connect(self.complex_to_real, self.vector_sink)

        self._running = False

    # -----------------------------------------------------------------------------
    # START SAFE
    # -----------------------------------------------------------------------------
    def start(self):
        if not self._running:
            super().start()
            self._running = True

    # -----------------------------------------------------------------------------
    # STOP SAFE (CRITICAL FOR HACKRF)
    # -----------------------------------------------------------------------------
    def stop(self):
        if self._running:
            try:
                super().stop()
                super().wait()
            except Exception:
                pass
            self._running = False

    # -----------------------------------------------------------------------------
    # GET CHIPS
    # -----------------------------------------------------------------------------
    def get_chips(self):

        data = self.vector_sink.data()

        if not data or len(data) < 1024:
            return None

        chips = np.array(data, dtype=np.float32)

        return chips

    # -----------------------------------------------------------------------------
    # CLEAR BUFFER
    # -----------------------------------------------------------------------------
    def clear(self):
        self.vector_sink.reset()

    # -----------------------------------------------------------------------------
    # DEBUG SIGNAL QUALITY (OPTIONAL)
    # -----------------------------------------------------------------------------
    def get_signal_power(self):

        data = self.vector_sink.data()

        if not data:
            return 0

        arr = np.array(data, dtype=np.float32)
        power = np.mean(arr ** 2)

        return power


# =============================================================================
# 🔥 CRITICAL FIX: ALIAS FOR IMPORT COMPATIBILITY
# =============================================================================
ZigbeeFlowgraph = ZigbeeIEEE802154Flowgraph
