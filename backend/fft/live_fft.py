# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/fft/live_fft.py
# VERSION:      v6.3.0 (SIGINT STANDARD - SIGNAL INTEGRITY FIX)
# UPDATED:      2026-03-20
# =============================================================================

# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# HackRF SDR
#     ↓
# SDRController (IQ file writer)
#     ↓
# LiveFFT (THIS FILE)
#     ↓
# ReconEngine
#     ↓
# SignalEngine
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# - Streaming correctness (tail read)
# - Real-time safe
# - Signal integrity FIRST
# - Non-breaking upgrades only
#
# =============================================================================
# CHANGE LOG
# =============================================================================
#
# v6.3.0
#   ✔ FIXED IQ conversion (correct I/Q split)
#   ✔ ADDED DC offset removal
#   ✔ ADDED window function (Hanning)
#   ✔ FIXED spectral leakage
#   ✔ FIXED flat FFT issue (~65 dB bug)
#   ✔ REDUCED smoothing (preserve transient signals)
#
# =============================================================================

import numpy as np
import threading
import time
import os


class LiveFFT:
    """
    Live FFT Engine (SIGINT Standard)
    """

    def __init__(self, sdr_controller, fft_size=2048):
        self.sdr = sdr_controller
        self.fft_size = fft_size

        self.running = False
        self.thread = None

        self.latest_frame = None
        self.latest_frame_ts = None

        # Internal state
        self._last_frame = None

    # =========================================================================
    # START
    # =========================================================================
    def start(self):

        print("📊 [FFT] Starting")

        if not self.sdr:
            raise RuntimeError("SDR not attached")

        if not self.sdr.get_state().get("running"):
            raise RuntimeError("SDR not running")

        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

        print("📊 [FFT] Started")

    # =========================================================================
    # MAIN LOOP
    # =========================================================================
    def _run(self):

        iq_path = self.sdr.iq_path

        while self.running:
            try:
                # ---------------------------------------------------------
                # Ensure file exists
                # ---------------------------------------------------------
                if not os.path.exists(iq_path):
                    time.sleep(0.1)
                    continue

                file_size = os.path.getsize(iq_path)

                # ---------------------------------------------------------
                # Wait until enough data is available
                # ---------------------------------------------------------
                if file_size < self.fft_size * 2:
                    time.sleep(0.05)
                    continue

                # ---------------------------------------------------------
                # STREAMING (TAIL READ)
                # ---------------------------------------------------------
                with open(iq_path, "rb") as f:
                    f.seek(-self.fft_size * 2, os.SEEK_END)
                    raw = f.read(self.fft_size * 2)

                if len(raw) < self.fft_size * 2:
                    time.sleep(0.05)
                    continue

                # ---------------------------------------------------------
                # IQ CONVERSION (CORRECT)
                # ---------------------------------------------------------
                iq_raw = np.frombuffer(raw, dtype=np.int8).astype(np.float32)

                i = iq_raw[0::2]
                q = iq_raw[1::2]

                iq = i + 1j * q

                # ---------------------------------------------------------
                # REMOVE DC OFFSET (CRITICAL)
                # ---------------------------------------------------------
                iq = iq - np.mean(iq)

                # ---------------------------------------------------------
                # WINDOW FUNCTION (CRITICAL)
                # ---------------------------------------------------------
                window = np.hanning(len(iq))
                iq_windowed = iq * window

                # ---------------------------------------------------------
                # FFT COMPUTATION
                # ---------------------------------------------------------
                fft = np.fft.fftshift(np.fft.fft(iq_windowed))

                power = 20 * np.log10(np.abs(fft) + 1e-6)

                # ---------------------------------------------------------
                # REMOVE DC SPIKE (CENTER BIN)
                # ---------------------------------------------------------
                center = len(power) // 2
                power[center] = np.min(power)

                # ---------------------------------------------------------
                # LIGHT SMOOTHING (SAFE)
                # ---------------------------------------------------------
                if self._last_frame is not None:
                    power = 0.9 * power + 0.1 * self._last_frame

                self._last_frame = power
                self.latest_frame = power
                self.latest_frame_ts = time.time()

            except Exception as e:
                print(f"🔥 [FFT ERROR] {e}")
                time.sleep(0.1)

    # =========================================================================
    # STOP
    # =========================================================================
    def stop(self):
        print("📊 [FFT] Stopped")
        self.running = False

    # =========================================================================
    # STATE
    # =========================================================================
    def is_running(self):
        return self.running

    # =========================================================================
    # DATA ACCESS
    # =========================================================================
    def get_latest_frame(self):
        return self.latest_frame

    def get_latest_frame_timestamp(self):
        return self.latest_frame_ts
