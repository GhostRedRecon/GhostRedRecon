# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF OFDM SUPPRESSOR
# FILE:         backend/recon/protocols/ofdm_suppressor.py
#
# VERSION:      v2.0.0 (PHASE-3 OFDM GRID SUPPRESSION + PROTOCOL HINT SAFETY)
# UPDATED:      2026-03-16
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance platform for red-team spectrum
# intelligence. The platform must avoid over-fragmenting wideband OFDM-like
# transmissions into dozens of synthetic emitters.
#
# This suppressor is used as a higher-confidence, whole-window OFDM detector.
# Unlike OFDMCollapseEngine, which groups local contiguous clusters, this
# module evaluates whether a large population of peaks across a window shows
# OFDM-like density and spacing characteristics and should be replaced with a
# single logical wideband emitter.
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# PeakDetector
#     ↓
# RFOFDMSuppressor     ← THIS MODULE
#     ↓
# EmitterClusterEngine
#     ↓
# FeatureExtractor
#     ↓
# ProtocolFingerprint
#     ↓
# ProtocolClassifier
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. GRID-LIKE CARRIER EVALUATION
# -----------------------------------------------------------------------------
# OFDM-like transmissions often produce many narrow peaks with relatively small
# inter-peak spacing.
#
#
# 2. WINDOW-LEVEL DECISION
# -----------------------------------------------------------------------------
# This module inspects a broad set of peaks and decides whether the entire
# group should be suppressed into one wideband emitter.
#
#
# 3. PROTOCOL HINT SAFETY
# -----------------------------------------------------------------------------
# Generic OFDM detection should not hardcode WiFi unless evidence exists.
#
#
# 4. SCHEMA COMPATIBILITY
# -----------------------------------------------------------------------------
# Supports freq_mhz / rf_frequency_mhz and power_db / rf_power_db.
#
#
# 5. LOW FALSE-POSITIVE BEHAVIOR
# -----------------------------------------------------------------------------
# Suppression is only applied when density, spacing, and bandwidth jointly
# suggest OFDM-like structure.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • detecting OFDM-like carrier grids
# • estimating center frequency and occupied bandwidth
# • collapsing a dense OFDM-like window into one logical emitter
# • exporting suppression evidence for downstream stages
#
#
# This module is NOT responsible for:
#
# • packet decoding
# • protocol-specific final classification
# • device fingerprinting
# • emitter tracking
#
#
# =============================================================================

from __future__ import annotations

import copy
import statistics
from typing import Any, Dict, List, Optional


class RFOFDMSuppressor:
    """
    Window-level OFDM-like suppressor.

    Intended for cases where a large peak population across a frequency region
    clearly behaves like one OFDM-style wideband transmission.
    """

    VERSION = "2.0.0"

    MIN_PEAKS_FOR_OFDM = 18
    MAX_MEDIAN_CARRIER_SPACING_MHZ = 0.25
    MIN_OFDM_BANDWIDTH_MHZ = 5.0
    MIN_PEAK_DENSITY = 4.5

    def suppress(self, peaks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not peaks:
            return peaks

        normalized = []
        passthrough = []

        for peak in peaks:
            if not isinstance(peak, dict):
                passthrough.append(peak)
                continue

            freq = self._get_float(
                peak.get("rf_frequency_mhz"),
                peak.get("freq_mhz"),
                peak.get("frequency_mhz"),
            )
            if freq is None:
                passthrough.append(peak)
                continue

            item = copy.deepcopy(peak)
            item["_freq_mhz"] = freq
            item["_power_db"] = self._get_float(
                peak.get("rf_power_db"),
                peak.get("power_db"),
                -100.0,
            )
            normalized.append(item)

        if len(normalized) < self.MIN_PEAKS_FOR_OFDM:
            return peaks

        normalized.sort(key=lambda p: p["_freq_mhz"])
        decision = self._assess_ofdm_window(normalized)

        if not decision["suppress"]:
            return peaks

        collapsed = self._build_suppressed_emitter(normalized, decision)
        return [collapsed] + passthrough

    # ------------------------------------------------------------------
    # DECISION LOGIC
    # ------------------------------------------------------------------

    def _assess_ofdm_window(self, peaks: List[Dict[str, Any]]) -> Dict[str, Any]:
        freqs = [p["_freq_mhz"] for p in peaks]
        powers = [p["_power_db"] for p in peaks]

        bandwidth = freqs[-1] - freqs[0] if len(freqs) > 1 else 0.0
        peak_count = len(freqs)
        density = peak_count / bandwidth if bandwidth > 0 else float(peak_count)

        spacings = [
            freqs[i] - freqs[i - 1]
            for i in range(1, len(freqs))
        ]
        median_spacing = statistics.median(spacings) if spacings else None
        p90_power = self._percentile(powers, 90.0)

        evidence = []
        penalties = []
        score = 0.0

        if peak_count >= self.MIN_PEAKS_FOR_OFDM:
            score += 0.28
            evidence.append("high_peak_count")
        else:
            penalties.append("insufficient_peak_count")

        if bandwidth >= self.MIN_OFDM_BANDWIDTH_MHZ:
            score += 0.22
            evidence.append("wideband_occupancy")
        else:
            penalties.append("bandwidth_too_narrow")

        if median_spacing is not None and median_spacing <= self.MAX_MEDIAN_CARRIER_SPACING_MHZ:
            score += 0.24
            evidence.append("tight_carrier_spacing")
        else:
            penalties.append("carrier_spacing_too_wide")

        if density >= self.MIN_PEAK_DENSITY:
            score += 0.16
            evidence.append("high_peak_density")
        else:
            penalties.append("density_too_low")

        if p90_power is not None:
            score += 0.05
            evidence.append("usable_power_presence")

        confidence = round(max(0.0, min(score, 0.98)), 2)

        suppress = (
            peak_count >= self.MIN_PEAKS_FOR_OFDM
            and bandwidth >= self.MIN_OFDM_BANDWIDTH_MHZ
            and median_spacing is not None
            and median_spacing <= self.MAX_MEDIAN_CARRIER_SPACING_MHZ
            and density >= self.MIN_PEAK_DENSITY
            and confidence >= 0.60
        )

        protocol_hint = self._infer_protocol_hint(freqs, bandwidth)

        return {
            "suppress": suppress,
            "confidence": confidence,
            "peak_count": peak_count,
            "bandwidth_mhz": round(bandwidth, 3),
            "density": round(density, 3),
            "median_spacing_mhz": round(median_spacing, 4) if median_spacing is not None else None,
            "center_freq_mhz": round(statistics.mean(freqs), 4) if freqs else None,
            "representative_power_db": round(statistics.median(powers), 2) if powers else -100.0,
            "peak_power_db": round(max(powers), 2) if powers else -100.0,
            "protocol_hint": protocol_hint,
            "evidence": evidence[:10],
            "penalties": penalties[:10],
        }

    # ------------------------------------------------------------------
    # EMITTER BUILD
    # ------------------------------------------------------------------

    def _build_suppressed_emitter(
        self,
        peaks: List[Dict[str, Any]],
        decision: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocol_hint = decision["protocol_hint"]
        protocol_confidence = decision["confidence"]

        return {
            "freq_mhz": decision["center_freq_mhz"],
            "rf_frequency_mhz": decision["center_freq_mhz"],

            "power_db": decision["representative_power_db"],
            "rf_power_db": decision["representative_power_db"],
            "rf_peak_power_db": decision["peak_power_db"],

            "bandwidth_mhz": decision["bandwidth_mhz"],
            "rf_bandwidth_mhz": decision["bandwidth_mhz"],

            "rf_modulation_hint": "OFDM_like",
            "rf_modulation_confidence": decision["confidence"],

            "rf_protocol_hint": protocol_hint,
            "rf_protocol_confidence": protocol_confidence if protocol_hint != "unknown" else round(protocol_confidence * 0.75, 2),

            "rf_signal_class": "wideband",
            "rf_ofdm_carriers": decision["peak_count"],
            "rf_ofdm_density": decision["density"],
            "rf_ofdm_median_spacing_mhz": decision["median_spacing_mhz"],
            "rf_ofdm_suppressed": True,
            "rf_ofdm_suppression_confidence": decision["confidence"],

            "rf_protocol_evidence": decision["evidence"],
            "rf_protocol_penalties": decision["penalties"],

            "rf_detection_stage": "ofdm_suppressor",
            "rf_collapse_engine": "RFOFDMSuppressor",
            "rf_collapse_engine_version": self.VERSION,
        }

    # ------------------------------------------------------------------
    # PROTOCOL HINTS
    # ------------------------------------------------------------------

    def _infer_protocol_hint(self, freqs: List[float], bandwidth_mhz: float) -> str:
        if not freqs:
            return "unknown"

        center = statistics.mean(freqs)

        if 2400.0 <= center <= 2485.0 and bandwidth_mhz >= 8.0:
            return "WiFi"

        if 5000.0 <= center <= 5900.0 and bandwidth_mhz >= 8.0:
            return "WiFi"

        if 2400.0 <= center <= 2485.0 and 1.0 <= bandwidth_mhz <= 5.0:
            return "Zigbee_like"

        return "unknown"

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _percentile(self, values: List[float], percentile: float) -> Optional[float]:
        if not values:
            return None
        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]

        rank = (len(ordered) - 1) * (percentile / 100.0)
        lower = int(rank)
        upper = min(lower + 1, len(ordered) - 1)
        weight = rank - lower
        return ordered[lower] * (1.0 - weight) + ordered[upper] * weight

    def _get_float(self, *values: Any) -> Optional[float]:
        for value in values:
            if value is None:
                continue
            try:
                v = float(value)
                if v != v:
                    continue
                if v in (float("inf"), float("-inf")):
                    continue
                return v
            except Exception:
                continue
        return None
