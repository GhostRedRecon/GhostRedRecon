# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         zigbee_phy_engine.py
# VERSION:      v2.0.0 (SIGINT PHY ENGINE - DSSS + AGC + SNR)
# UPDATED:      2026-03-25
# =============================================================================

import numpy as np


class ZigbeePHYEngine:
    """
    SIGINT-Grade Zigbee PHY Engine (Fallback Layer)

    Responsibilities:
    - Signal conditioning (AGC)
    - Energy detection
    - DSSS chip extraction
    - Correlation-based validation
    - Basic frame extraction
    """

    def __init__(self, sample_rate=2_000_000):

        self.sample_rate = sample_rate

        # Zigbee DSSS reference (simplified pattern)
        self.dsss_reference = np.array([
            1, -1, 1, 1, -1, -1, 1, -1,
            1, 1, -1, 1, -1, 1, -1, -1,
            1, -1, -1, 1, 1, -1, 1, -1,
            -1, 1, 1, -1, 1, -1, -1, 1
        ])

        # Thresholds (tuned for SDR noise)
        self.energy_threshold = 1e-6
        self.correlation_threshold = 0.5

        self.debug = False

    # -----------------------------------------------------------------------------
    # MAIN PROCESS
    # -----------------------------------------------------------------------------
    def process(self, iq_samples):

        if iq_samples is None or len(iq_samples) < 1024:
            return None

        # ---------------------------------------------------------
        # STEP 1: AGC (Normalize signal)
        # ---------------------------------------------------------
        iq_samples = self._apply_agc(iq_samples)

        # ---------------------------------------------------------
        # STEP 2: Energy Detection
        # ---------------------------------------------------------
        energy = self._compute_energy(iq_samples)

        if energy < self.energy_threshold:
            if self.debug:
                print(f"[PHY] Weak signal energy: {energy}")
            return None

        # ---------------------------------------------------------
        # STEP 3: Convert to chips
        # ---------------------------------------------------------
        chips = self._extract_chips(iq_samples)

        if chips is None:
            return None

        # ---------------------------------------------------------
        # STEP 4: DSSS Correlation
        # ---------------------------------------------------------
        score = self._correlate(chips)

        if self.debug:
            print(f"[PHY] Correlation score: {score:.3f}")

        if score < self.correlation_threshold:
            return None

        # ---------------------------------------------------------
        # STEP 5: Frame extraction (basic)
        # ---------------------------------------------------------
        frame = self._extract_frame(chips)

        return frame

    # -----------------------------------------------------------------------------
    # AGC
    # -----------------------------------------------------------------------------
    def _apply_agc(self, iq):

        power = np.mean(np.abs(iq) ** 2)

        if power == 0:
            return iq

        gain = 1.0 / np.sqrt(power)

        return iq * gain

    # -----------------------------------------------------------------------------
    # ENERGY
    # -----------------------------------------------------------------------------
    def _compute_energy(self, iq):

        return np.mean(np.abs(iq) ** 2)

    # -----------------------------------------------------------------------------
    # CHIP EXTRACTION
    # -----------------------------------------------------------------------------
    def _extract_chips(self, iq):

        # Convert to real signal
        real_signal = np.real(iq)

        # Normalize
        real_signal = real_signal / (np.max(np.abs(real_signal)) + 1e-9)

        # Slice into binary chips
        chips = np.where(real_signal > 0, 1, -1)

        if len(chips) < 64:
            return None

        return chips

    # -----------------------------------------------------------------------------
    # DSSS CORRELATION
    # -----------------------------------------------------------------------------
    def _correlate(self, chips):

        ref = self.dsss_reference

        if len(chips) < len(ref):
            return 0

        correlations = []

        # Sliding window correlation
        for i in range(0, len(chips) - len(ref), len(ref)):
            window = chips[i:i + len(ref)]

            corr = np.dot(window, ref) / len(ref)
            correlations.append(corr)

        if not correlations:
            return 0

        return max(correlations)

    # -----------------------------------------------------------------------------
    # FRAME EXTRACTION (SIMPLIFIED)
    # -----------------------------------------------------------------------------
    def _extract_frame(self, chips):

        # Convert chips back to bits (very rough fallback)
        bits = ((chips + 1) // 2).astype(np.uint8)

        # Pack into bytes
        try:
            byte_arr = np.packbits(bits[:256])
        except Exception:
            return None

        if len(byte_arr) < 5:
            return None

        return byte_arr.tobytes()
