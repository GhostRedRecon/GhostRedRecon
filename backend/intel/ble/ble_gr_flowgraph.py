# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/ble/ble_gr_flowgraph.py
# VERSION:      v4.0.0 (SIGINT BLE DEMOD — SYMBOL PATH HARDENING)
# UPDATED:      2026-04-02
# =============================================================================

from __future__ import annotations

from typing import Optional

def ble_gnuradio_available():
    try:
        from gnuradio import gr  # noqa: F401
        import osmosdr  # noqa: F401
        return True
    except Exception:
        return False


class BLEFlowgraph:

    SYMBOL_RATE = 1_000_000
    TARGET_SPS = 2

    def __init__(self, freq=2402e6, samp_rate=4e6, gain=40, iq_path: Optional[str] = None):
        if not ble_gnuradio_available():
            raise RuntimeError("GNU Radio / osmosdr BLE backend unavailable")

        from gnuradio import gr, blocks, analog, filter, digital
        import osmosdr

        self._gr = gr
        self._top = gr.top_block("BLE SIGINT Decoder v4")

        self.freq = freq
        self.samp_rate = float(samp_rate)
        self.channel_rate = float(self.SYMBOL_RATE * self.TARGET_SPS)
        self.quad_gain = self.samp_rate / (2.0 * 3.141592653589793 * 250000.0)
        self.resample_decim = max(1, int(round(self.samp_rate / self.channel_rate)))

        # ============================================================
        # SDR SOURCE
        # ============================================================
        self.source = None
        self._iq_char_to_complex = None
        self._source_mode = "hackrf"

        if iq_path:
            self._source_mode = "iq_file"
            self.source = blocks.file_source(gr.sizeof_char, iq_path, False)
            # Normalize HackRF int8 IQ into a stable range for the GFSK chain.
            self._iq_char_to_complex = blocks.interleaved_char_to_complex(False, 128.0)
        else:
            self.source = osmosdr.source(args="hackrf=0")

            self.source.set_sample_rate(self.samp_rate)
            self.source.set_center_freq(self.freq)
            try:
                self.source.set_bandwidth(2_000_000)
            except Exception:
                pass

            # Better gain handling
            self.source.set_gain(gain)
            try:
                self.source.set_if_gain(24)
                self.source.set_bb_gain(24)
            except Exception:
                pass

        # ============================================================
        # FRONT-END CLEANUP
        # ============================================================
        self.dc_block = filter.dc_blocker_cc(64, True)
        self.channel_filter = filter.fir_filter_ccf(
            1,
            filter.firdes.low_pass(
                1.0,
                self.samp_rate,
                1_000_000,
                250_000,
            )
        )

        # ============================================================
        # AGC
        # ============================================================
        self.agc = analog.agc2_cc(
            attack_rate=5e-2,
            decay_rate=1e-3,
            reference=1.0,
            gain=1.0
        )

        # ============================================================
        # GFSK DEMOD
        # ============================================================
        self.demod = analog.quadrature_demod_cf(self.quad_gain)
        self.float_dc_block = filter.dc_blocker_ff(64, True)

        # ============================================================
        # RESAMPLE TO 2 SAMPLES / SYMBOL
        # ============================================================
        self.resampler = filter.rational_resampler_fff(
            interpolation=1,
            decimation=self.resample_decim,
            taps=[],
            fractional_bw=0.0,
        )
        self.symbol_filter = filter.fir_filter_fff(
            1,
            [0.15, 0.35, 0.35, 0.15]
        )

        # ============================================================
        # SYMBOL TIMING
        # ============================================================
        self.clock_recovery = digital.clock_recovery_mm_ff(
            omega=float(self.TARGET_SPS),
            gain_omega=0.01,
            mu=0.5,
            gain_mu=0.03,
            omega_relative_limit=0.02
        )

        # ============================================================
        # BINARY SLICER
        # ============================================================
        self.slicer = digital.binary_slicer_fb()

        # ============================================================
        # OUTPUT
        # ============================================================
        self.sink = blocks.vector_sink_b()

        # ============================================================
        # CONNECTIONS
        # ============================================================
        if self._source_mode == "iq_file":
            self._top.connect(self.source, self._iq_char_to_complex)
            self._top.connect(self._iq_char_to_complex, self.dc_block)
        else:
            self._top.connect(self.source, self.dc_block)
        self._top.connect(self.dc_block, self.channel_filter)
        self._top.connect(self.channel_filter, self.agc)
        self._top.connect(self.agc, self.demod)
        self._top.connect(self.demod, self.float_dc_block)
        self._top.connect(self.float_dc_block, self.resampler)
        self._top.connect(self.resampler, self.symbol_filter)
        self._top.connect(self.symbol_filter, self.clock_recovery)
        self._top.connect(self.clock_recovery, self.slicer)
        self._top.connect(self.slicer, self.sink)

    def start(self):
        self._top.start()

    def stop(self):
        self._top.stop()
        self._top.wait()

    # =========================================================================
    def get_data(self):
        data = self.sink.data()
        self.sink.reset()
        return list(data)
