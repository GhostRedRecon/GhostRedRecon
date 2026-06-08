# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       WIFI COLLAPSE ENGINE
# FILE:         backend/recon/protocols/wifi_detector.py
#
# VERSION:      v6.0.0 (PHASE-3 WIFI COLLAPSE DETERMINISM + CLUSTER HARDENING)
# UPDATED:      2026-03-16
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance and SIGINT platform for red-team
# spectrum intelligence. The platform detects, clusters, tracks, enriches,
# classifies, and fingerprints wireless emitters across WiFi, BLE, Zigbee,
# Sub-GHz telemetry, remote-control RF, and other wireless ecosystems.
#
# This module collapses multiple FFT / peak-derived OFDM-like carrier
# detections that likely belong to the same IEEE 802.11 transmission into a
# single logical WiFi emitter representation.
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# PeakDetector / BurstDetector / WidebandDetector
#       ↓
# EmitterClusterEngine
#       ↓
# RFWifiCollapseEngine   ← THIS MODULE
#       ↓
# ProtocolFingerprintEngine
#       ↓
# ProtocolClassifier
#       ↓
# Device Intelligence / Fusion / Identity Layers
#
# This module does NOT decode WiFi frames. It performs protocol-aware spectral
# collapse and produces a cleaner emitter abstraction for downstream protocol
# inference.
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PROTOCOL-AWARE COLLAPSE
#    Multiple OFDM subcarrier peaks from one WiFi transmission should not
#    survive as separate emitters downstream.
#
# 2. CHANNEL-CENTER REPRESENTATION
#    WiFi emitters are normalized to known IEEE 802.11 channel centers.
#
# 3. EVIDENCE-BASED HEURISTICS
#    Collapse should only occur when enough local evidence suggests WiFi-like
#    OFDM morphology.
#
# 4. SCHEMA TOLERANCE
#    Accept legacy and current GhostRecon emitter schemas safely.
#
# 5. NON-DESTRUCTIVE PIPELINE BEHAVIOR
#    Non-WiFi emitters pass through unchanged.
#
# 6. REAL-TIME SAFE
#    Heuristics are lightweight and suitable for live reconnaissance loops.
#
# 7. DETERMINISTIC CLUSTERING
#    Collapse behavior should not depend on iteration order or seed choice.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# RFWifiCollapseEngine IS responsible for:
# • identifying WiFi-like multi-carrier groups
# • collapsing grouped carriers into a single logical emitter
# • estimating representative channel center and power
# • aligning emitters to nearest valid WiFi channel center
# • surfacing collapse evidence and ambiguity metadata
#
# RFWifiCollapseEngine is NOT responsible for:
# • packet decoding
# • demodulation
# • final protocol arbitration
# • vendor or product identification
# • emitter lifecycle management
#
# =============================================================================

from __future__ import annotations

import copy
import logging
import statistics
from typing import Any, Dict, List, Optional, Tuple


class RFWifiCollapseEngine:
    """
    Protocol-aware WiFi OFDM carrier collapse engine.

    Input:
        emitter dictionaries produced by upstream recon stages.

    Output:
        a list where WiFi-like multi-carrier detections are collapsed into a
        single logical emitter aligned to an IEEE 802.11 channel center.
    """

    VERSION = "6.0.0"

    WIFI_24_CHANNELS_MHZ = [
        2412.0, 2417.0, 2422.0, 2427.0, 2432.0, 2437.0, 2442.0,
        2447.0, 2452.0, 2457.0, 2462.0, 2467.0, 2472.0, 2484.0,
    ]

    WIFI_5_CHANNELS_MHZ = [
        5180.0, 5200.0, 5220.0, 5240.0, 5260.0, 5280.0, 5300.0, 5320.0,
        5500.0, 5520.0, 5540.0, 5560.0, 5580.0, 5600.0, 5620.0, 5640.0,
        5660.0, 5680.0, 5700.0, 5745.0, 5765.0, 5785.0, 5805.0, 5825.0,
    ]

    WIFI_CHANNEL_CENTERS_MHZ = WIFI_24_CHANNELS_MHZ + WIFI_5_CHANNELS_MHZ

    DEFAULT_WIFI_CHANNEL_WIDTH_MHZ = 20.0

    # cluster contiguity threshold between adjacent emitters
    CLUSTER_GAP_MHZ = 2.2

    # min local emitter count to consider OFDM WiFi collapse
    MIN_WIFI_CARRIER_COUNT = 3

    # spread checks
    MIN_SPREAD_MHZ = 3.5
    MAX_NARROW_SPREAD_REJECTION_MHZ = 2.2
    MAX_WIFI_SPREAD_MHZ = 30.0

    # nearest valid WiFi center tolerance
    CHANNEL_SNAP_TOLERANCE_MHZ = 12.0

    # evidence thresholds
    STRONG_CONFIDENCE = 0.70
    MIN_WIFI_CONFIDENCE = 0.42

    def __init__(self) -> None:
        self.logger = logging.getLogger("ghostrecon.wifi")

    # -------------------------------------------------------------------------
    # PUBLIC API
    # -------------------------------------------------------------------------

    def collapse(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collapse WiFi-like OFDM carrier groups into logical WiFi emitters.

        Non-WiFi emitters pass through unchanged.
        """
        if not emitters:
            return emitters

        normalized, passthrough = self._normalize_emitters(emitters)

        if not normalized:
            return emitters

        clusters = self._build_contiguous_clusters(normalized)

        collapsed_emitters: List[Dict[str, Any]] = []
        non_wifi_emitters: List[Dict[str, Any]] = []

        for cluster in clusters:
            assessment = self.assess_cluster(cluster)

            if assessment["is_wifi_like"]:
                collapsed_emitters.append(self._collapse_cluster(cluster, assessment))
            else:
                non_wifi_emitters.extend(
                    self._strip_internal_fields(emitter)
                    for emitter in cluster
                )

        result = collapsed_emitters + non_wifi_emitters + passthrough

        self.logger.debug(
            "WiFi collapse | input=%d normalized=%d clusters=%d collapsed=%d passthrough=%d",
            len(emitters),
            len(normalized),
            len(clusters),
            len(collapsed_emitters),
            len(passthrough),
        )

        return result

    def assess_cluster(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Public assessment API for datacheck/debugging and downstream validation.
        """
        return self._assess_wifi_likelihood(cluster)

    # -------------------------------------------------------------------------
    # NORMALIZATION
    # -------------------------------------------------------------------------

    def _normalize_emitters(
        self,
        emitters: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Any]]:
        normalized: List[Dict[str, Any]] = []
        passthrough: List[Any] = []

        for emitter in emitters:
            if not isinstance(emitter, dict):
                passthrough.append(emitter)
                continue

            freq = self._get_float(
                emitter.get("freq_mhz"),
                emitter.get("rf_frequency_mhz"),
                emitter.get("frequency_mhz"),
                emitter.get("center_freq_mhz"),
            )

            if freq is None:
                passthrough.append(emitter)
                continue

            enriched = copy.deepcopy(emitter)
            enriched["_wifi_collapse_freq_mhz"] = freq
            enriched["_wifi_collapse_power_db"] = self._get_float(
                emitter.get("power_db"),
                emitter.get("rf_power_db"),
                emitter.get("signal_power_db"),
                -100.0,
            )
            normalized.append(enriched)

        normalized.sort(key=lambda e: e["_wifi_collapse_freq_mhz"])
        return normalized, passthrough

    # -------------------------------------------------------------------------
    # CLUSTERING
    # -------------------------------------------------------------------------

    def _build_contiguous_clusters(
        self,
        emitters: List[Dict[str, Any]],
    ) -> List[List[Dict[str, Any]]]:
        if not emitters:
            return []

        clusters: List[List[Dict[str, Any]]] = []
        current = [emitters[0]]

        for emitter in emitters[1:]:
            prev_freq = current[-1]["_wifi_collapse_freq_mhz"]
            freq = emitter["_wifi_collapse_freq_mhz"]

            if abs(freq - prev_freq) <= self.CLUSTER_GAP_MHZ:
                current.append(emitter)
            else:
                clusters.append(current)
                current = [emitter]

        clusters.append(current)
        return clusters

    # -------------------------------------------------------------------------
    # WIFI-LIKELIHOOD ASSESSMENT
    # -------------------------------------------------------------------------

    def _assess_wifi_likelihood(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        freqs = sorted(
            e["_wifi_collapse_freq_mhz"]
            for e in cluster
            if e.get("_wifi_collapse_freq_mhz") is not None
        )

        if not freqs:
            return self._empty_assessment()

        centroid = statistics.mean(freqs)
        spread = max(freqs) - min(freqs) if len(freqs) > 1 else 0.0
        carrier_count = len(freqs)
        nearest_channel, channel_delta = self._nearest_wifi_channel(centroid)

        evidence: List[str] = []
        penalties: List[str] = []
        score = 0.0

        if carrier_count >= self.MIN_WIFI_CARRIER_COUNT:
            score += 0.30
            evidence.append("multi_carrier_cluster")
        else:
            penalties.append("insufficient_carrier_count")

        if self.MIN_SPREAD_MHZ <= spread <= self.MAX_WIFI_SPREAD_MHZ:
            score += 0.22
            evidence.append("ofdm_like_spread")
        elif spread <= self.MAX_NARROW_SPREAD_REJECTION_MHZ:
            score -= 0.18
            penalties.append("cluster_too_narrow_for_wifi_ofdm")
        else:
            penalties.append("spread_out_of_wifi_range")

        if nearest_channel is not None and channel_delta <= self.CHANNEL_SNAP_TOLERANCE_MHZ:
            proximity_bonus = max(0.10, 0.24 * (1.0 - (channel_delta / self.CHANNEL_SNAP_TOLERANCE_MHZ)))
            score += proximity_bonus
            evidence.append("near_wifi_channel_center")
        else:
            score -= 0.14
            penalties.append("far_from_wifi_channel_center")

        band = self._detect_band(centroid)
        if band in {"2.4ghz", "5ghz"}:
            score += 0.10
            evidence.append(f"{band}_wifi_band")
        else:
            score -= 0.10
            penalties.append("not_in_wifi_band")

        bandwidth_hint = self._estimate_cluster_bandwidth(cluster, spread)
        if bandwidth_hint is not None:
            if bandwidth_hint >= 16.0:
                score += 0.12
                evidence.append("20mhz_wifi_like_bandwidth_hint")
            elif bandwidth_hint >= 8.0:
                score += 0.07
                evidence.append("partial_wifi_like_bandwidth_hint")
            else:
                penalties.append("bandwidth_hint_too_narrow")

        spacing_score = self._cluster_spacing_score(freqs)
        if spacing_score >= 0.60:
            score += 0.08
            evidence.append("consistent_multicarrier_spacing")
        elif spacing_score <= 0.20 and carrier_count >= self.MIN_WIFI_CARRIER_COUNT:
            penalties.append("irregular_spacing_pattern")

        confidence = round(self._clamp(score, 0.0, 0.98), 2)

        ambiguous = bool(
            confidence >= 0.40
            and (
                (channel_delta is not None and channel_delta > 7.5)
                or spread < self.MIN_SPREAD_MHZ + 1.0
                or carrier_count <= self.MIN_WIFI_CARRIER_COUNT
            )
        )

        is_wifi_like = (
            carrier_count >= self.MIN_WIFI_CARRIER_COUNT
            and nearest_channel is not None
            and channel_delta is not None
            and channel_delta <= self.CHANNEL_SNAP_TOLERANCE_MHZ
            and spread >= self.MIN_SPREAD_MHZ
            and confidence >= self.MIN_WIFI_CONFIDENCE
        )

        return {
            "is_wifi_like": is_wifi_like,
            "confidence": confidence,
            "carrier_count": carrier_count,
            "spread_mhz": round(spread, 3),
            "centroid_mhz": round(centroid, 3),
            "nearest_channel_mhz": nearest_channel,
            "channel_delta_mhz": round(channel_delta, 3) if channel_delta is not None else None,
            "band": band,
            "evidence": evidence[:10],
            "penalties": penalties[:10],
            "bandwidth_hint_mhz": bandwidth_hint,
            "ambiguous": ambiguous,
            "spacing_score": round(spacing_score, 3),
            "decision_state": self._decision_state(confidence, ambiguous),
        }

    def _empty_assessment(self) -> Dict[str, Any]:
        return {
            "is_wifi_like": False,
            "confidence": 0.0,
            "carrier_count": 0,
            "spread_mhz": 0.0,
            "centroid_mhz": None,
            "nearest_channel_mhz": None,
            "channel_delta_mhz": None,
            "band": "unknown",
            "evidence": [],
            "penalties": ["empty_cluster"],
            "bandwidth_hint_mhz": None,
            "ambiguous": False,
            "spacing_score": 0.0,
            "decision_state": "low_observability",
        }

    # -------------------------------------------------------------------------
    # COLLAPSE
    # -------------------------------------------------------------------------

    def _collapse_cluster(
        self,
        cluster: List[Dict[str, Any]],
        assessment: Dict[str, Any],
    ) -> Dict[str, Any]:
        freqs = [
            e["_wifi_collapse_freq_mhz"]
            for e in cluster
            if e.get("_wifi_collapse_freq_mhz") is not None
        ]

        powers = [
            self._get_float(e.get("_wifi_collapse_power_db"), -100.0)
            for e in cluster
        ]

        nearest_channel = assessment["nearest_channel_mhz"]
        center_estimate = statistics.mean(freqs) if freqs else nearest_channel
        representative_power = statistics.median(powers) if powers else -100.0
        peak_power = max(powers) if powers else -100.0
        estimated_bw = assessment["bandwidth_hint_mhz"] or self.DEFAULT_WIFI_CHANNEL_WIDTH_MHZ

        merged = self._merge_useful_fields(cluster)

        collapsed = {
            "freq_mhz": float(nearest_channel),
            "rf_frequency_mhz": float(nearest_channel),

            "bandwidth_mhz": round(max(estimated_bw, self.DEFAULT_WIFI_CHANNEL_WIDTH_MHZ), 2),
            "rf_bandwidth_mhz": round(max(estimated_bw, self.DEFAULT_WIFI_CHANNEL_WIDTH_MHZ), 2),

            "power_db": round(representative_power, 2),
            "rf_power_db": round(representative_power, 2),
            "rf_peak_power_db": round(peak_power, 2),

            "rf_protocol": "WiFi",
            "rf_protocol_hint": "WiFi",
            "rf_protocol_family": "IEEE 802.11",
            "rf_protocol_confidence": assessment["confidence"],
            "rf_protocol_hint_confidence": assessment["confidence"],

            "rf_wifi_carriers": assessment["carrier_count"],
            "rf_wifi_center_estimate": round(center_estimate, 3),
            "rf_wifi_channel_center_mhz": float(nearest_channel),
            "rf_wifi_channel_delta_mhz": assessment["channel_delta_mhz"],
            "rf_wifi_spread_mhz": assessment["spread_mhz"],
            "rf_wifi_band": assessment["band"],
            "rf_wifi_collapse_confidence": assessment["confidence"],
            "rf_wifi_collapse_ambiguous": assessment["ambiguous"],
            "rf_wifi_spacing_score": assessment["spacing_score"],

            "rf_protocol_evidence": assessment["evidence"][:10],
            "rf_protocol_penalties": assessment["penalties"][:10],
            "rf_protocol_explanation": self._build_explanation(assessment),

            "rf_signal_class": "wideband",
            "rf_ofdm_likelihood": round(min(0.55 + (assessment["confidence"] * 0.45), 0.98), 2),

            "rf_detection_stage": "wifi_collapse",
            "rf_collapse_engine": "RFWifiCollapseEngine",
            "rf_collapse_engine_version": self.VERSION,
            "rf_source_emitter_count": len(cluster),
        }

        collapsed.update(merged)
        return collapsed

    # -------------------------------------------------------------------------
    # FIELD MERGING
    # -------------------------------------------------------------------------

    def _merge_useful_fields(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}

        burst_durations = []
        duty_cycles = []

        for emitter in cluster:
            burst = self._get_float(
                emitter.get("rf_burst_duration"),
                emitter.get("burst_duration"),
                emitter.get("rf_burst_duration_sec"),
            )
            if burst is not None:
                burst_durations.append(burst)

            duty = self._get_float(
                emitter.get("rf_duty_cycle"),
                emitter.get("duty_cycle"),
            )
            if duty is not None:
                duty_cycles.append(duty)

        if burst_durations:
            merged["rf_burst_duration"] = round(statistics.median(burst_durations), 4)

        if duty_cycles:
            merged["rf_duty_cycle"] = round(statistics.median(duty_cycles), 4)

        return merged

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    def _estimate_cluster_bandwidth(
        self,
        cluster: List[Dict[str, Any]],
        spread_mhz: float,
    ) -> Optional[float]:
        explicit_bandwidths = []

        for emitter in cluster:
            bw = self._get_float(
                emitter.get("bandwidth_mhz"),
                emitter.get("rf_bandwidth_mhz"),
                emitter.get("occupied_bandwidth_mhz"),
                emitter.get("rf_bandwidth_mhz_estimate"),
            )
            if bw is not None and bw > 0:
                explicit_bandwidths.append(bw)

        if explicit_bandwidths:
            return round(max(statistics.median(explicit_bandwidths), spread_mhz, 1.0), 2)

        if spread_mhz >= 18.0:
            return 20.0
        if spread_mhz >= 9.0:
            return 10.0
        if spread_mhz >= 4.0:
            return 8.0
        return None

    def _cluster_spacing_score(self, freqs: List[float]) -> float:
        if len(freqs) < 3:
            return 0.0

        spacings = [freqs[i] - freqs[i - 1] for i in range(1, len(freqs))]
        positive = [s for s in spacings if s > 0]
        if not positive:
            return 0.0

        mean_spacing = statistics.mean(positive)
        if mean_spacing <= 0:
            return 0.0

        if len(positive) == 1:
            return 0.5

        stdev = statistics.pstdev(positive)
        normalized = stdev / mean_spacing if mean_spacing > 0 else 1.0
        return self._clamp(1.0 - normalized, 0.0, 1.0)

    def _nearest_wifi_channel(self, freq_mhz: Optional[float]) -> Tuple[Optional[float], Optional[float]]:
        if freq_mhz is None:
            return None, None

        nearest = min(self.WIFI_CHANNEL_CENTERS_MHZ, key=lambda c: abs(c - freq_mhz))
        delta = abs(nearest - freq_mhz)
        return float(nearest), float(delta)

    def _detect_band(self, freq: Optional[float]) -> str:
        if freq is None:
            return "unknown"
        if 2400.0 <= freq <= 2485.0:
            return "2.4ghz"
        if 4900.0 <= freq <= 5900.0:
            return "5ghz"
        return "unknown"

    def _decision_state(self, confidence: float, ambiguous: bool) -> str:
        if confidence < 0.28:
            return "low_observability"
        if ambiguous:
            return "contested"
        if confidence >= self.STRONG_CONFIDENCE:
            return "stable"
        return "provisional"

    def _build_explanation(self, assessment: Dict[str, Any]) -> str:
        parts = [
            f"wifi_confidence={assessment['confidence']:.2f}",
            f"centroid={assessment['centroid_mhz']}",
            f"channel={assessment['nearest_channel_mhz']}",
            f"delta={assessment['channel_delta_mhz']}",
            f"carriers={assessment['carrier_count']}",
            f"spread={assessment['spread_mhz']}",
            f"spacing_score={assessment['spacing_score']}",
            f"state={assessment['decision_state']}",
        ]
        if assessment["evidence"]:
            parts.append("evidence=" + ",".join(assessment["evidence"][:6]))
        if assessment["penalties"]:
            parts.append("penalties=" + ",".join(assessment["penalties"][:4]))
        return " | ".join(parts)

    def _strip_internal_fields(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        out = copy.deepcopy(emitter)
        out.pop("_wifi_collapse_freq_mhz", None)
        out.pop("_wifi_collapse_power_db", None)
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

    def _clamp(self, value: float, low: float, high: float) -> float:
        return max(low, min(high, value))
