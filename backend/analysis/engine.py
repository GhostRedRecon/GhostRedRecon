# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/analysis/engine.py
# VERSION:      v7.0.0 (ANALYSIS CONSOLIDATION)
# LAST UPDATED: 2026-02-22
#
# =============================================================================
# ARCHITECTURE OVERVIEW (v7)
# =============================================================================
# This module consolidates analysis heuristics into a single cohesive engine.
#
# Typical usage:
#   DemodEngine (analysis.demod) → bitstream → AnalysisEngine → intel output
#
#   - Modulation classification (very lightweight)
#   - Frame segmentation (preamble stripping + frame candidate extraction)
#   - Protocol stats (entropy + rolling score)
#   - Rolling counter detection (between frames)
#   - Encoding detection + symbol-rate estimation live in analysis.demod
#
# =============================================================================
# CHANGES (v7.0.0)
# =============================================================================
# - Merged the following into this single module:
#     * modulation_classifier.py
#     * frame_segmenter.py
#     * decoder_profile.py
#     * protocol_analyzer.py
#     * rolling_counter_analyzer.py
#     * encoding_detector.py
#     * symbol_rate_estimator.py
# - Preserved public class names for drop-in imports.
# - Added AnalysisEngine (new) as a convenience orchestrator.
# =============================================================================

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np


# =============================================================================
# From modulation_classifier.py
# =============================================================================

class ModulationClassifier:
    def classify(self, iq_samples):
        if iq_samples is None or len(iq_samples) == 0:
            return "unknown"
        amplitude_var = np.var(np.abs(iq_samples))
        phase_var = np.var(np.angle(iq_samples))
        if amplitude_var > phase_var:
            return "OOK"
        return "FSK"


# =============================================================================
# From frame_segmenter.py
# =============================================================================

class FrameSegmenter:
    def segment(self, bitstream: str) -> dict:
        if not bitstream or len(bitstream) < 32:
            return {"frame_length": None, "frame_bits": None, "preamble_length": None}

        preamble_len = 0
        for i in range(min(32, len(bitstream) - 1)):
            if bitstream[i] != bitstream[i + 1]:
                preamble_len += 1
            else:
                break

        payload = bitstream[preamble_len:]

        frame_length = None
        for size in range(32, min(256, len(payload) // 2)):
            if payload[:size] == payload[size:size * 2]:
                frame_length = size
                break

        if frame_length is None:
            frame_length = min(128, len(payload))

        frame_bits = payload[:frame_length]

        return {
            "frame_length": frame_length,
            "frame_bits": frame_bits,
            "preamble_length": preamble_len,
        }


# =============================================================================
# From decoder_profile.py
# =============================================================================

@dataclass
class DecoderProfile:
    preferred_modulations: List[str]
    decode_mode: str
    expected_bandwidth_khz: List[int]
    expected_symbol_rates: List[int]
    rolling_expected: Optional[bool]


class DecoderProfileSelector:
    DEFAULT_PROFILE = DecoderProfile(
        preferred_modulations=["unknown"],
        decode_mode="intel",
        expected_bandwidth_khz=[],
        expected_symbol_rates=[],
        rolling_expected=None,
    )

    @staticmethod
    def from_category(category_metadata: dict) -> DecoderProfile:
        decoding = category_metadata.get("decoding")
        if not decoding:
            return DecoderProfileSelector.DEFAULT_PROFILE

        return DecoderProfile(
            preferred_modulations=decoding.get("preferred_modulations", ["unknown"]),
            decode_mode=decoding.get("decode_mode", "intel"),
            expected_bandwidth_khz=decoding.get("expected_bandwidth_khz", []),
            expected_symbol_rates=decoding.get("expected_symbol_rates", []),
            rolling_expected=decoding.get("rolling_expected"),
        )


# =============================================================================
# From protocol_analyzer.py
# =============================================================================

class ProtocolAnalyzer:
    def __init__(self):
        self._recent_frames = deque(maxlen=10)

    def analyze(self, bitstream: str):
        if not bitstream or len(bitstream) < 16:
            return None

        entropy = self._shannon_entropy(bitstream)
        frame_length = len(bitstream)
        rolling_score = self._rolling_score(bitstream)

        is_probably_static = entropy < 0.3
        is_probably_rolling = entropy > 0.6 and rolling_score > 0.4

        self._recent_frames.append(bitstream)

        return {
            "frame_length": frame_length,
            "entropy": round(entropy, 3),
            "rolling_score": round(rolling_score, 3),
            "is_probably_static": is_probably_static,
            "is_probably_rolling": is_probably_rolling,
        }

    def _shannon_entropy(self, bits: str):
        p0 = bits.count("0") / len(bits)
        p1 = bits.count("1") / len(bits)

        entropy = 0.0
        for p in (p0, p1):
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _rolling_score(self, current_bits: str):
        if not self._recent_frames:
            return 0.0
        last = self._recent_frames[-1]
        if len(last) != len(current_bits):
            return 0.0
        hamming = sum(c1 != c2 for c1, c2 in zip(last, current_bits))
        return hamming / len(current_bits)


# =============================================================================
# From rolling_counter_analyzer.py
# =============================================================================

class RollingCounterAnalyzer:
    def analyze(self, previous_frame: str, current_frame: str) -> dict:
        base = {
            "is_probably_rolling": False,
            "counter_bit_range": None,
            "counter_increment_detected": False,
        }

        if not previous_frame or not current_frame:
            return base
        if len(previous_frame) != len(current_frame):
            return base

        changing_bits = [i for i in range(len(previous_frame)) if previous_frame[i] != current_frame[i]]
        if not changing_bits:
            return base

        start = min(changing_bits)
        end = max(changing_bits)

        try:
            prev_val = int(previous_frame[start:end + 1], 2)
            curr_val = int(current_frame[start:end + 1], 2)
            increment_detected = curr_val == (prev_val + 1)
        except Exception:
            increment_detected = False

        return {
            "is_probably_rolling": True,
            "counter_bit_range": (start, end),
            "counter_increment_detected": increment_detected,
        }


# =============================================================================
# New: AnalysisEngine (v7 convenience orchestrator)
# =============================================================================

class AnalysisEngine:
    """
    Orchestrates analysis around demod outputs.

    Expected demod_result schema (from analysis.demod.DemodEngine):
      {
        "bitstream": list[int],
        "symbol_rate": int|None,
        "encoding": str,
        "entropy": float,
        "bit_length": int
      }

    This engine normalizes to a string bitstream for protocol tools.
    """

    def __init__(self):
        self._protocol = ProtocolAnalyzer()
        self._segmenter = FrameSegmenter()
        self._rolling = RollingCounterAnalyzer()

        self._last_frame_bits: Optional[str] = None

    @staticmethod
    def _bits_to_string(bitstream: Union[str, List[int]]) -> Optional[str]:
        if bitstream is None:
            return None
        if isinstance(bitstream, str):
            return bitstream
        try:
            return "".join("1" if int(b) else "0" for b in bitstream)
        except Exception:
            return None

    def analyze_demod(self, demod_result: Dict[str, Any], category_metadata: Optional[dict] = None) -> Optional[Dict[str, Any]]:
        if not demod_result:
            return None

        bitstream_str = self._bits_to_string(demod_result.get("bitstream"))
        if not bitstream_str:
            return None

        # Profile (optional, category-driven)
        profile = DecoderProfileSelector.from_category(category_metadata or {})

        # Frame segmentation
        seg = self._segmenter.segment(bitstream_str)
        frame_bits = seg.get("frame_bits") or bitstream_str

        # Protocol heuristics
        proto = self._protocol.analyze(frame_bits)

        # Rolling counter (delta vs previous)
        rolling = None
        if self._last_frame_bits is not None and len(self._last_frame_bits) == len(frame_bits):
            rolling = self._rolling.analyze(self._last_frame_bits, frame_bits)

        self._last_frame_bits = frame_bits

        return {
            "profile": {
                "preferred_modulations": profile.preferred_modulations,
                "decode_mode": profile.decode_mode,
                "expected_bandwidth_khz": profile.expected_bandwidth_khz,
                "expected_symbol_rates": profile.expected_symbol_rates,
                "rolling_expected": profile.rolling_expected,
            },
            "demod": {
                "symbol_rate": demod_result.get("symbol_rate"),
                "encoding": demod_result.get("encoding"),
                "entropy": demod_result.get("entropy"),
                "bit_length": demod_result.get("bit_length"),
            },
            "segmentation": seg,
            "protocol": proto,
            "rolling_counter": rolling,
            "frame_bits": frame_bits,
        }
