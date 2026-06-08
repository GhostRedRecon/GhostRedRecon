"""Adaptive RF peak detector.

Converts one FFT spectrum frame into frequency/power peak records. The class is
kept intentionally lightweight because it runs in the real-time RF pipeline.
"""

from __future__ import annotations

from typing import Iterable

import numpy as np


class PeakDetector:
    """Hybrid threshold and top-N fallback peak detector."""

    def __init__(self) -> None:
        self.noise_percentile = 20
        self.threshold_offset = 1.5
        self.min_snr = 1.0
        self.min_distance = 3
        self.top_n_fallback = 12
        self.debug = False

    def detect_peaks(self, spectrum: Iterable[float], center_freq_mhz: float, sample_rate_hz: float) -> list[dict]:
        if spectrum is None:
            return []

        spectrum_array = np.asarray(spectrum, dtype=np.float32)
        if spectrum_array.size == 0:
            return []

        noise_floor = float(np.percentile(spectrum_array, self.noise_percentile))
        threshold = noise_floor + self.threshold_offset
        peaks: list[dict] = []

        for index in range(1, spectrum_array.size - 1):
            power = float(spectrum_array[index])
            if power <= spectrum_array[index - 1] and power <= spectrum_array[index + 1]:
                continue
            if power < threshold:
                continue

            snr = power - noise_floor
            if snr < self.min_snr or power < noise_floor + 0.5:
                continue

            peaks.append(
                {
                    "bin": int(index),
                    "freq_mhz": self._bin_to_freq(index, spectrum_array.size, center_freq_mhz, sample_rate_hz),
                    "power": power,
                    "snr": snr,
                }
            )

        if len(peaks) < 5:
            fallback_count = min(self.top_n_fallback, spectrum_array.size)
            for index in np.argsort(spectrum_array)[-fallback_count:]:
                power = float(spectrum_array[index])
                peaks.append(
                    {
                        "bin": int(index),
                        "freq_mhz": self._bin_to_freq(int(index), spectrum_array.size, center_freq_mhz, sample_rate_hz),
                        "power": power,
                        "snr": power - noise_floor,
                    }
                )

        filtered = self._suppress_close_peaks(peaks)
        if self.debug and filtered:
            print(
                f"[PEAK] noise={noise_floor:.2f} thr={threshold:.2f} "
                f"max={float(spectrum_array.max()):.2f} peaks={len(filtered)}"
            )
        return filtered

    @staticmethod
    def _bin_to_freq(bin_index: int, fft_size: int, center_freq_mhz: float, sample_rate_hz: float) -> float:
        freq_offset_hz = (bin_index - fft_size / 2) * sample_rate_hz / fft_size
        return center_freq_mhz + (freq_offset_hz / 1e6)

    def _suppress_close_peaks(self, peaks: list[dict]) -> list[dict]:
        if not peaks:
            return []

        filtered: list[dict] = []
        for peak in sorted(peaks, key=lambda item: item["power"], reverse=True):
            if all(abs(peak["bin"] - kept["bin"]) >= self.min_distance for kept in filtered):
                filtered.append(peak)
        return filtered
