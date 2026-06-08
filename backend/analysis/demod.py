# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/analysis/demod.py
# VERSION:      v7.0.0 (ANALYSIS CONSOLIDATION)
# LAST UPDATED: 2026-02-22
#
# =============================================================================
# ARCHITECTURE OVERVIEW (v7)
# =============================================================================
# SDR (IQ) → Analysis.DemodEngine → bitstream (+ symbol_rate, encoding, entropy)
#                                ↘ optional Demodulators (OOKDemodulator, etc.)
#
# This module is intentionally "signal-processing only":
#   - No SDR access
#   - No API access
#   - No recon/intel coupling
#
# =============================================================================
# CHANGES (v7.0.0)
# =============================================================================
# - Merged the following into this single module:
#     * demod_engine.py
#     * demodulators/base_demod.py
#     * demodulators/ook_demod.py
# - Preserved public class names:
#     * DemodEngine
#     * BaseDemodulator
#     * OOKDemodulator
# - No functional changes intended beyond removing cross-file imports.
# =============================================================================

from __future__ import annotations

import logging
import math
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import numpy as np

log = logging.getLogger("ghostrecon.demod")


# =============================================================================
# Demodulator interface + reference implementation (from demodulators/)
# =============================================================================

class BaseDemodulator(ABC):
    @abstractmethod
    def demodulate(self, iq_samples, sample_rate) -> Optional[Dict[str, Any]]:
        """
        Returns:
            {
                "bitstream": str,
                "symbol_rate": float,
                "confidence": float
            }
        """
        raise NotImplementedError


class OOKDemodulator(BaseDemodulator):
    def demodulate(self, iq_samples, sample_rate) -> Optional[Dict[str, Any]]:
        if iq_samples is None or len(iq_samples) == 0:
            return None

        envelope = np.abs(iq_samples)
        threshold = np.mean(envelope) + (0.5 * np.std(envelope))
        bits = (envelope > threshold).astype(int)

        transitions = np.sum(np.abs(np.diff(bits)))
        duration_sec = len(bits) / sample_rate if sample_rate else 0
        symbol_rate = transitions / duration_sec if duration_sec > 0 else 0

        bitstream = "".join(str(b) for b in bits[:512])

        return {
            "bitstream": bitstream,
            "symbol_rate": float(symbol_rate),
            "confidence": 0.7,
        }


# =============================================================================
# DemodEngine (from demod_engine.py)
# =============================================================================

class SymbolRateEstimator:
    def estimate(self, digital_signal, sample_rate):
        if len(digital_signal) < 10:
            return None
        edges = np.where(np.diff(digital_signal) != 0)[0]
        if len(edges) < 5:
            return None
        intervals = np.diff(edges)
        if len(intervals) < 5:
            return None

        hist, bins = np.histogram(intervals, bins=20)
        dominant_idx = int(np.argmax(hist))
        dominant_interval = (bins[dominant_idx] + bins[dominant_idx + 1]) / 2
        if dominant_interval <= 0:
            return None
        symbol_rate = sample_rate / dominant_interval
        return int(symbol_rate)


class EncodingDetector:
    def detect(self, digital_signal):
        if len(digital_signal) < 20:
            return "unknown"

        transitions = np.sum(np.diff(digital_signal) != 0)
        transition_density = transitions / len(digital_signal)

        if transition_density > 0.4:
            return "manchester"

        pulse_lengths = self._pulse_lengths(digital_signal)
        if pulse_lengths is not None:
            unique_lengths = np.unique(pulse_lengths)
            if len(unique_lengths) >= 2:
                return "pwm"

        return "nrz"

    def _pulse_lengths(self, signal):
        lengths = []
        current = signal[0]
        count = 1
        for bit in signal[1:]:
            if bit == current:
                count += 1
            else:
                lengths.append(count)
                current = bit
                count = 1
        lengths.append(count)
        if len(lengths) < 5:
            return None
        return np.array(lengths)


class DemodEngine:
    """
    Converts IQ samples into digital intelligence.

    Returns (backward compatible schema):
      {
        "bitstream": list[int]   (original behavior)
        "symbol_rate": int|None
        "encoding": str
        "entropy": float
        "bit_length": int
      }

    NOTE: Some downstream analyzers prefer a string bitstream.
          That conversion belongs in analysis.engine.py to avoid breaking callers.
    """

    def __init__(self):
        self._symbol_estimator = SymbolRateEstimator()
        self._encoding_detector = EncodingDetector()

    def analyze(self, iq_samples, sample_rate):
        if iq_samples is None or len(iq_samples) < 32:
            return None

        try:
            envelope = np.abs(iq_samples)
            envelope = envelope / (np.max(envelope) + 1e-9)

            threshold = np.mean(envelope) + 0.5 * np.std(envelope)
            digital_signal = (envelope > threshold).astype(int)

            symbol_rate = self._symbol_estimator.estimate(digital_signal, sample_rate)
            encoding = self._encoding_detector.detect(digital_signal)

            bitstream = self._extract_bits(digital_signal, sample_rate, symbol_rate)
            if not bitstream:
                return None

            entropy = self._calculate_entropy(bitstream)

            return {
                "bitstream": bitstream,
                "symbol_rate": symbol_rate,
                "encoding": encoding,
                "entropy": entropy,
                "bit_length": len(bitstream),
            }

        except Exception as e:
            log.error(f"Demod error: {e}", exc_info=True)
            return None

    def _extract_bits(self, digital_signal, sample_rate, symbol_rate):
        if not symbol_rate or symbol_rate <= 0:
            return None
        samples_per_symbol = int(sample_rate / symbol_rate)
        if samples_per_symbol <= 0:
            return None

        bits = []
        for i in range(0, len(digital_signal), samples_per_symbol):
            chunk = digital_signal[i:i + samples_per_symbol]
            if len(chunk) < samples_per_symbol:
                break
            bit = int(np.mean(chunk) > 0.5)
            bits.append(bit)

        if len(bits) < 8:
            return None
        return bits

    def _calculate_entropy(self, bitstream):
        if not bitstream:
            return 0.0
        ones = sum(bitstream)
        zeros = len(bitstream) - ones
        p1 = ones / len(bitstream)
        p0 = zeros / len(bitstream)

        entropy = 0.0
        for p in (p0, p1):
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)
