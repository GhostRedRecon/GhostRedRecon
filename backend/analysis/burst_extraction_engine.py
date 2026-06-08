# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/analysis/burst_extraction_engine.py
# VERSION:      v1.0.0 (SIGINT BURST EXTRACTION ENGINE)
# UPDATED:      2026-03-22
# =============================================================================

import numpy as np
import time
import uuid


class BurstExtractionEngine:
    """
    =============================================================================
    🧠 ARCHITECTURE
    =============================================================================

    IQ Stream → Power Envelope → Adaptive Threshold → State Machine → Burst

    =============================================================================
    🎯 RESPONSIBILITY
    =============================================================================

    - Detect RF transmission bursts
    - Extract clean IQ segments
    - Provide structured burst objects for intelligence layers

    =============================================================================
    🔥 DESIGN PRINCIPLES
    =============================================================================

    1. ADAPTIVE → works in noisy environments
    2. STATEFUL → avoids fragmentation
    3. LOSSLESS → preserves IQ data
    4. REAL-TIME SAFE → low latency

    =============================================================================
    """

    def __init__(
        self,
        sample_rate=2_000_000,
        min_burst_samples=256,
        end_silence_samples=128,
        threshold_k=3.0,
    ):

        self.sample_rate = sample_rate
        self.min_burst_samples = min_burst_samples
        self.end_silence_samples = end_silence_samples
        self.threshold_k = threshold_k

        self.state = "IDLE"

        self.current_burst = []
        self.silence_counter = 0

        self.noise_floor = None

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def process_iq(self, iq_samples, center_freq_mhz):

        bursts = []

        # Convert to power
        power = np.abs(iq_samples) ** 2

        # Update noise floor
        self._update_noise_floor(power)

        threshold = self.noise_floor + (self.threshold_k * np.std(power))

        for i, p in enumerate(power):

            if self.state == "IDLE":

                if p > threshold:
                    self.state = "ACTIVE"
                    self.current_burst = [iq_samples[i]]
                    self.silence_counter = 0

            elif self.state == "ACTIVE":

                self.current_burst.append(iq_samples[i])

                if p < threshold:
                    self.silence_counter += 1
                else:
                    self.silence_counter = 0

                # END CONDITION
                if self.silence_counter > self.end_silence_samples:

                    if len(self.current_burst) >= self.min_burst_samples:
                        burst = self._finalize_burst(center_freq_mhz)
                        bursts.append(burst)

                    self.state = "IDLE"
                    self.current_burst = []
                    self.silence_counter = 0

        return bursts

    # =========================================================================
    # NOISE FLOOR
    # =========================================================================
    def _update_noise_floor(self, power):

        median = np.median(power)

        if self.noise_floor is None:
            self.noise_floor = median
        else:
            # Smooth update
            self.noise_floor = 0.9 * self.noise_floor + 0.1 * median

    # =========================================================================
    # FINALIZE BURST
    # =========================================================================
    def _finalize_burst(self, center_freq_mhz):

        iq = np.array(self.current_burst)

        power = np.abs(iq) ** 2

        duration_ms = (len(iq) / self.sample_rate) * 1000

        snr = self._estimate_snr(power)

        return {
            "burst_id": str(uuid.uuid4()),
            "timestamp": time.time(),

            "num_samples": len(iq),
            "duration_ms": duration_ms,

            "center_freq_mhz": center_freq_mhz,

            "avg_power": float(np.mean(power)),
            "max_power": float(np.max(power)),

            "snr_estimate": snr,

            "iq_samples": iq,   # 🔥 CRITICAL FOR NEXT STAGES
        }

    # =========================================================================
    # SNR ESTIMATION
    # =========================================================================
    def _estimate_snr(self, power):

        signal_power = np.mean(power)
        noise_power = self.noise_floor if self.noise_floor else 1e-6

        return float(10 * np.log10(signal_power / (noise_power + 1e-6)))
