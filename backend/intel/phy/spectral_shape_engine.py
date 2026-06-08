# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/spectral_shape_engine.py
# VERSION:      v1.0.0 (SPECTRAL SHAPE INTELLIGENCE ENGINE)
# LAST UPDATED: 2026-03-08
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# ReconEngine
#     ↓
# SpectralShapeEngine (THIS FILE)
#     ↓
# ProtocolEngine
#     ↓
# ZigbeeBLEInferenceEngine
#     ↓
# RFPhysicalFingerprintEngine
#     ↓
# Intel API
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
#
# Extract spectral structure features from FFT slices in order to improve
# protocol detection and RF intelligence classification.
#
# This module provides:
#
#   ✔ spectral width estimation
#   ✔ spectral flatness (OFDM vs narrowband)
#   ✔ spectral symmetry detection
#   ✔ peak structure detection
#   ✔ chirp pattern hints (LoRa-like)
#   ✔ multi-peak detection (FHSS hints like BLE)
#
# These features allow higher layers to distinguish:
#
#   WiFi OFDM
#   BLE / GFSK
#   Zigbee DSSS
#   LoRa chirps
#   narrowband OOK / FSK
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# ✔ deterministic
# ✔ safe under noisy SDR conditions
# ✔ no state accumulation
# ✔ minimal compute overhead
# ✔ no demodulation required
# ✔ real-time safe for live recon loops
#
# =============================================================================
# OUTPUT FEATURES
# =============================================================================
#
# spectral_peak_power
# spectral_width_bins
# spectral_flatness
# spectral_symmetry
# spectral_peak_count
# spectral_chirp_hint
#
# =============================================================================

import numpy as np
from typing import Dict, Optional


class SpectralShapeEngine:

    # =========================================================================
    # PUBLIC ENTRYPOINT
    # =========================================================================

    def extract(self, spectrum: np.ndarray) -> Optional[Dict]:

        try:
            return self._analyze(spectrum)
        except Exception:
            return None

    # =========================================================================
    # CORE ANALYSIS
    # =========================================================================

    def _analyze(self, spectrum: np.ndarray) -> Optional[Dict]:

        if spectrum is None or len(spectrum) < 32:
            return None

        s = np.array(spectrum, dtype=np.float32)

        mean_power = np.mean(s)
        std_power = np.std(s)

        if std_power < 1e-9:
            return None

        peak_power = np.max(s)

        # ---------------------------------------------------------------------
        # ACTIVE BINS (signal above noise)
        # ---------------------------------------------------------------------

        threshold = mean_power + (1.5 * std_power)

        active = s > threshold
        active_idx = np.where(active)[0]

        if len(active_idx) == 0:
            width_bins = 0
        else:
            width_bins = active_idx[-1] - active_idx[0]

        # ---------------------------------------------------------------------
        # SPECTRAL FLATNESS
        # ---------------------------------------------------------------------

        flatness = std_power / (mean_power + 1e-9)

        # ---------------------------------------------------------------------
        # EDGE SYMMETRY
        # ---------------------------------------------------------------------

        half = len(s) // 2

        left_slope = np.mean(np.diff(s[:half]))
        right_slope = np.mean(np.diff(s[half:]))

        symmetry = 1.0 - min(1.0, abs(left_slope + right_slope))

        # ---------------------------------------------------------------------
        # PEAK DETECTION
        # ---------------------------------------------------------------------

        peaks = 0

        for i in range(1, len(s) - 1):

            if s[i] > s[i - 1] and s[i] > s[i + 1] and s[i] > threshold:
                peaks += 1

        # ---------------------------------------------------------------------
        # CHIRP DETECTION (LoRa-like)
        # ---------------------------------------------------------------------

        diff = np.diff(s)

        chirp_hint = float(np.std(diff))

        return {
            "spectral_peak_power": float(peak_power),
            "spectral_width_bins": int(width_bins),
            "spectral_flatness": float(flatness),
            "spectral_symmetry": float(symmetry),
            "spectral_peak_count": int(peaks),
            "spectral_chirp_hint": chirp_hint
        }
