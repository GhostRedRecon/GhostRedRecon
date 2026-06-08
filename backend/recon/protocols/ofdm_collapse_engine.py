# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       OFDM PEAK COLLAPSE ENGINE
# FILE:         backend/recon/protocols/ofdm_collapse_engine.py
#
# VERSION:      v2.0.0 (PHASE-3 OFDM CLUSTER COLLAPSE + EVIDENCE UPGRADE)
# UPDATED:      2026-03-16
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance and device-intelligence platform
# built for red-team spectrum operations. The system observes, clusters,
# fingerprints, classifies, and tracks RF emitters across WiFi, Zigbee, BLE,
# telemetry, remote-control RF, and other wireless ecosystems.
#
# This module collapses dense groups of FFT / peak detections that likely
# belong to one wideband OFDM-like transmission into a single canonical
# emitter abstraction for downstream clustering and protocol analysis.
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# LiveFFT
#     ↓
# PeakDetector
#     ↓
# OFDMCollapseEngine    ← THIS MODULE
#     ↓
# EmitterClusterEngine
#     ↓
# RFEmitterTracker
#     ↓
# ProtocolFingerprint / ProtocolClassifier
#
#
# Modern OFDM protocols can produce multiple adjacent spectral peaks because of
# subcarriers, leakage, spectral shoulders, and FFT fragmentation.
#
# Without collapse, the pipeline may incorrectly treat one physical
# transmission as many emitters.
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. DETERMINISTIC CLUSTERING
# -----------------------------------------------------------------------------
# Adjacent peaks are grouped using stable frequency-gap rules.
#
#
# 2. EVIDENCE-BASED COLLAPSE
# -----------------------------------------------------------------------------
# Only sufficiently dense and sufficiently wide clusters are collapsed.
#
#
# 3. SCHEMA TOLERANCE
# -----------------------------------------------------------------------------
# Supports legacy and current peak schemas:
#   freq_mhz / rf_frequency_mhz
#   power_db / rf_power_db
#
#
# 4. REAL-TIME SAFE
# -----------------------------------------------------------------------------
# Lightweight heuristics suitable for live SDR pipelines.
#
#
# 5. NON-DESTRUCTIVE PIPELINE BEHAVIOR
# -----------------------------------------------------------------------------
# Small or weak clusters pass through unchanged.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • detecting dense OFDM-like peak clusters
# • collapsing clusters into single logical emitters
# • estimating cluster center frequency
# • estimating bandwidth and representative power
# • exposing collapse evidence for downstream consumers
#
#
# This module is NOT responsible for:
#
# • emitter tracking
# • device identification
# • final protocol classification
# • packet decoding
#
#
# =============================================================================

from __future__ import annotations

import copy
import statistics
from typing import Any, Dict, List, Optional


class OFDMCollapseEngine:
    """
    Generic OFDM-like peak collapse engine.

    This engine works before protocol-specific stages. It is intentionally
    conservative: only dense, contiguous, sufficiently wide clusters are
    collapsed into a single emitter.
    """

    VERSION = "2.0.0"

    MAX_CLUSTER_GAP_MHZ = 1.75
    MIN_CLUSTER_SIZE = 6
    MIN_COLLAPSE_BANDWIDTH_MHZ = 3.5
    MIN_PEAK_DENSITY_PER_MHZ = 1.5

    def collapse(self, peaks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not peaks:
            return peaks

        normalized = []
        passthrough = []

        for peak in peaks:
            if not isinstance(peak, dict):
                passthrough.append(peak)
                continue

            freq = self._get_float(
                peak.get("freq_mhz"),
                peak.get("rf_frequency_mhz"),
                peak.get("frequency_mhz"),
            )

            if freq is None:
                passthrough.append(peak)
                continue

            item = copy.deepcopy(peak)
            item["_ofdm_freq_mhz"] = freq
            item["_ofdm_power_db"] = self._get_float(
                peak.get("power_db"),
                peak.get("rf_power_db"),
                -100.0,
            )
            normalized.append(item)

        if len(normalized) < self.MIN_CLUSTER_SIZE:
            return peaks

        normalized.sort(key=lambda p: p["_ofdm_freq_mhz"])

        clusters: List[List[Dict[str, Any]]] = []
        current = [normalized[0]]

        for peak in normalized[1:]:
            if abs(peak["_ofdm_freq_mhz"] - current[-1]["_ofdm_freq_mhz"]) <= self.MAX_CLUSTER_GAP_MHZ:
                current.append(peak)
            else:
                clusters.append(current)
                current = [peak]

        clusters.append(current)

        emitters: List[Dict[str, Any]] = []

        for cluster in clusters:
            decision = self._should_collapse(cluster)

            if not decision["collapse"]:
                emitters.extend(self._strip_internal_fields(cluster))
                continue

            emitters.append(self._build_collapsed_emitter(cluster, decision))

        emitters.extend(passthrough)
        return emitters

    # ------------------------------------------------------------------
    # DECISION LOGIC
    # ------------------------------------------------------------------

    def _should_collapse(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        freqs = [p["_ofdm_freq_mhz"] for p in cluster]
        bandwidth = max(freqs) - min(freqs) if len(freqs) > 1 else 0.0
        peak_count = len(cluster)
        density = peak_count / bandwidth if bandwidth > 0 else float(peak_count)

        evidence = []
        penalties = []
        score = 0.0

        if peak_count >= self.MIN_CLUSTER_SIZE:
            score += 0.35
            evidence.append("sufficient_peak_count")
        else:
            penalties.append("insufficient_peak_count")

        if bandwidth >= self.MIN_COLLAPSE_BANDWIDTH_MHZ:
            score += 0.25
            evidence.append("sufficient_bandwidth")
        else:
            penalties.append("bandwidth_too_narrow")

        if density >= self.MIN_PEAK_DENSITY_PER_MHZ:
            score += 0.20
            evidence.append("high_peak_density")
        else:
            penalties.append("low_peak_density")

        spacings = [
            freqs[i] - freqs[i - 1]
            for i in range(1, len(freqs))
        ]
        if spacings:
            median_spacing = statistics.median(spacings)
            if median_spacing <= self.MAX_CLUSTER_GAP_MHZ:
                score += 0.10
                evidence.append("contiguous_spacing")
            else:
                penalties.append("fragmented_spacing")
        else:
            median_spacing = None

        confidence = round(max(0.0, min(score, 0.98)), 2)
        collapse = (
            peak_count >= self.MIN_CLUSTER_SIZE
            and bandwidth >= self.MIN_COLLAPSE_BANDWIDTH_MHZ
            and density >= self.MIN_PEAK_DENSITY_PER_MHZ
            and confidence >= 0.50
        )

        return {
            "collapse": collapse,
            "confidence": confidence,
            "peak_count": peak_count,
            "bandwidth_mhz": round(bandwidth, 3),
            "density_per_mhz": round(density, 3),
            "median_spacing_mhz": round(median_spacing, 4) if median_spacing is not None else None,
            "evidence": evidence[:10],
            "penalties": penalties[:10],
        }

    # ------------------------------------------------------------------
    # EMITTER BUILD
    # ------------------------------------------------------------------

    def _build_collapsed_emitter(
        self,
        cluster: List[Dict[str, Any]],
        decision: Dict[str, Any],
    ) -> Dict[str, Any]:
        freqs = [p["_ofdm_freq_mhz"] for p in cluster]
        powers = [p["_ofdm_power_db"] for p in cluster]

        center = statistics.mean(freqs)
        representative_power = statistics.median(powers)
        peak_power = max(powers)
        bandwidth = max(freqs) - min(freqs) if len(freqs) > 1 else 0.0

        return {
            "freq_mhz": round(center, 4),
            "rf_frequency_mhz": round(center, 4),

            "power_db": round(representative_power, 2),
            "rf_power_db": round(representative_power, 2),
            "rf_peak_power_db": round(peak_power, 2),

            "bandwidth_mhz": round(bandwidth, 3),
            "rf_bandwidth_mhz": round(bandwidth, 3),

            "confidence": decision["confidence"],
            "rf_confidence": decision["confidence"],

            "rf_modulation_hint": "OFDM_like",
            "rf_protocol_hint": "unknown",
            "rf_signal_class": "wideband",

            "rf_ofdm_peak_count": decision["peak_count"],
            "rf_ofdm_density_per_mhz": decision["density_per_mhz"],
            "rf_ofdm_median_spacing_mhz": decision["median_spacing_mhz"],
            "rf_ofdm_collapsed": True,
            "rf_ofdm_collapse_confidence": decision["confidence"],

            "rf_protocol_evidence": decision["evidence"],
            "rf_protocol_penalties": decision["penalties"],

            "rf_detection_stage": "ofdm_collapse",
            "rf_collapse_engine": "OFDMCollapseEngine",
            "rf_collapse_engine_version": self.VERSION,
        }

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _strip_internal_fields(self, cluster: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for item in cluster:
            clean = copy.deepcopy(item)
            clean.pop("_ofdm_freq_mhz", None)
            clean.pop("_ofdm_power_db", None)
            out.append(clean)
        return out

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
