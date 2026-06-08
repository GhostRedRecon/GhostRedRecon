# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF WIDEBAND PROTOCOL DETECTOR
# FILE:         backend/recon/protocols/wideband_detector.py
#
# VERSION:      v3.0.0 (PHASE-3 ENERGY-REGION WIDEBAND DETECTION UPGRADE)
# UPDATED:      2026-03-16
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance and spectrum-intelligence platform
# for red-team operations. The platform observes, detects, clusters,
# fingerprints, classifies, and enriches emitters across WiFi, BLE, Zigbee,
# sub-GHz telemetry, remote control RF, and other wireless ecosystems.
#
# This module performs early-stage wideband energy-region detection directly
# from FFT spectrum data. Its role is to identify contiguous spectral energy
# envelopes that may represent protocol-bearing emissions before downstream
# peak-based and protocol-specific stages refine the decision.
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# LiveFFT
#     ↓
# SpectralEnvironmentAnalyzer
#     ↓
# RFWidebandProtocolDetector   ← THIS MODULE
#     ↓
# PeakDetector / Wideband Candidate Path
#     ↓
# OFDM Collapse / WiFi Collapse / Protocol Fingerprint / Classifier
#
#
# This module is intentionally EARLY-STAGE and HEURISTIC.
# It provides protocol-like wideband hints, not final authoritative identity.
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. CONTIGUOUS ENERGY REGION DETECTION
# -----------------------------------------------------------------------------
# Detect broad active spectrum regions rather than isolated narrow peaks.
#
#
# 2. SDR NOISE TOLERANCE
# -----------------------------------------------------------------------------
# Use robust noise-floor estimation and thresholding tolerant to HackRF noise,
# spectral variation, and environmental instability.
#
#
# 3. LOW-LATENCY HEURISTICS
# -----------------------------------------------------------------------------
# Keep the detector lightweight for live spectrum sweeps and streaming use.
#
#
# 4. PROTOCOL-HINT SAFETY
# -----------------------------------------------------------------------------
# Emit protocol hypotheses only when bandwidth and band evidence are coherent.
# Avoid over-asserting protocol labels from bandwidth alone.
#
#
# 5. SCHEMA COMPATIBILITY
# -----------------------------------------------------------------------------
# Export both legacy and RF-prefixed fields for downstream compatibility.
#
#
# 6. EXPLAINABILITY
# -----------------------------------------------------------------------------
# Emit evidence, confidence, ambiguity, and decision-state metadata to support
# later arbitration by protocol fingerprint and classifier layers.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • detecting contiguous energy regions in FFT magnitude data
# • estimating region center frequency
# • estimating occupied bandwidth
# • generating early wideband protocol hypotheses
# • exposing evidence and confidence metadata
#
#
# This module is NOT responsible for:
#
# • final protocol arbitration
# • device identification
# • emitter lifecycle management
# • packet decoding
# • SDR control
#
# =============================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np


class RFWidebandProtocolDetector:
    """
    Early-stage wideband region detector.

    Input:
        FFT / spectrum magnitude array plus tuning metadata.

    Output:
        A wideband candidate emitter dictionary containing center frequency,
        bandwidth, protocol hints, evidence, and compatibility fields.

    Notes:
        - This detector is intentionally conservative.
        - It should generate protocol hints, not final truth.
        - Downstream stages should refine or override the result.
    """

    VERSION = "3.0.0"

    WIFI_24_CHANNELS_MHZ = [
        2412.0, 2417.0, 2422.0, 2427.0, 2432.0, 2437.0, 2442.0,
        2447.0, 2452.0, 2457.0, 2462.0, 2467.0, 2472.0, 2484.0,
    ]

    WIFI_5_CHANNELS_MHZ = [
        5180.0, 5200.0, 5220.0, 5240.0, 5260.0, 5280.0, 5300.0, 5320.0,
        5500.0, 5520.0, 5540.0, 5560.0, 5580.0, 5600.0, 5620.0, 5640.0,
        5660.0, 5680.0, 5700.0, 5745.0, 5765.0, 5785.0, 5805.0, 5825.0,
    ]

    BLE_ADV_CHANNELS_MHZ = [2402.0, 2426.0, 2480.0]

    ZIGBEE_CHANNELS_MHZ = [
        2405.0, 2410.0, 2415.0, 2420.0, 2425.0, 2430.0, 2435.0,
        2440.0, 2445.0, 2450.0, 2455.0, 2460.0, 2465.0, 2470.0, 2475.0,
    ]

    ACTIVE_THRESHOLD_DB = 6.0
    MIN_REGION_BINS = 4
    MIN_REGION_BANDWIDTH_HZ = 300_000.0
    MAX_REGIONS_TO_SCORE = 6

    MIN_PROTOCOL_CONFIDENCE = 0.18
    STRONG_PROTOCOL_CONFIDENCE = 0.55
    AMBIGUITY_MARGIN = 0.12

    def detect(
        self,
        spectrum: Sequence[float],
        center_freq_hz: float,
        sample_rate_hz: float,
    ) -> Optional[Dict[str, Any]]:
        """
        Detect the strongest wideband region and return one candidate result.

        For richer downstream workflows, prefer detect_candidates().
        """
        result = self.detect_candidates(
            spectrum=spectrum,
            center_freq_hz=center_freq_hz,
            sample_rate_hz=sample_rate_hz,
        )

        candidates = result.get("rf_wideband_candidates", [])
        if not candidates:
            return None

        best = candidates[0]
        second = candidates[1] if len(candidates) > 1 else None

        return {
            "rf_protocol": best["protocol"],
            "rf_protocol_hint": best["protocol"],
            "rf_protocol_family": best["family"],
            "rf_protocol_confidence": best["confidence"],

            "rf_frequency_mhz": best["freq_mhz"],
            "freq_mhz": best["freq_mhz"],

            "rf_bandwidth_mhz": best["bandwidth_mhz"],
            "bandwidth_mhz": best["bandwidth_mhz"],

            "rf_signal_class": "wideband",
            "rf_detection_stage": "wideband",

            "rf_protocol_candidates": candidates,
            "rf_protocol_evidence": result.get("rf_protocol_evidence", []),
            "rf_protocol_penalties": result.get("rf_protocol_penalties", []),
            "rf_protocol_ambiguous": result.get("rf_protocol_ambiguous", False),
            "rf_protocol_margin": result.get("rf_protocol_margin", 0.0),
            "rf_protocol_decision_state": result.get("rf_protocol_decision_state", "low_observability"),
            "rf_protocol_readiness_score": result.get("rf_protocol_readiness_score", 0.0),
            "rf_protocol_explanation": result.get("rf_protocol_explanation", "no_explanation"),

            "rf_secondary_protocol_hint": second["protocol"] if second else None,
            "rf_secondary_protocol_confidence": second["confidence"] if second else 0.0,

            "rf_noise_floor_db": result.get("rf_noise_floor_db"),
            "rf_active_region_count": result.get("rf_active_region_count", 0),
        }

    def detect_candidates(
        self,
        spectrum: Sequence[float],
        center_freq_hz: float,
        sample_rate_hz: float,
    ) -> Dict[str, Any]:
        """
        Detect and score wideband regions and emit ranked protocol candidates.
        """
        if spectrum is None:
            return self._empty_result("spectrum_missing")

        try:
            values = np.asarray(spectrum, dtype=float)
        except Exception:
            return self._empty_result("spectrum_invalid")

        if values.size == 0:
            return self._empty_result("spectrum_empty")

        if sample_rate_hz is None or sample_rate_hz <= 0:
            return self._empty_result("sample_rate_invalid")

        if center_freq_hz is None:
            return self._empty_result("center_freq_invalid")

        noise_floor = float(np.median(values))
        threshold = noise_floor + self.ACTIVE_THRESHOLD_DB
        active_mask = values > threshold

        raw_regions = self._regions(active_mask)
        if not raw_regions:
            return self._empty_result(
                "no_active_regions",
                noise_floor_db=round(noise_floor, 2),
            )

        bin_width_hz = float(sample_rate_hz) / float(len(values))

        regions = []
        for start, end in raw_regions:
            region_bins = end - start
            region_bandwidth_hz = region_bins * bin_width_hz
            if region_bins < self.MIN_REGION_BINS:
                continue
            if region_bandwidth_hz < self.MIN_REGION_BANDWIDTH_HZ:
                continue
            regions.append((start, end))

        if not regions:
            return self._empty_result(
                "regions_too_small",
                noise_floor_db=round(noise_floor, 2),
            )

        scored_regions = []
        for start, end in regions[: self.MAX_REGIONS_TO_SCORE]:
            region_result = self._score_region(
                values=values,
                start=start,
                end=end,
                center_freq_hz=center_freq_hz,
                sample_rate_hz=sample_rate_hz,
                noise_floor_db=noise_floor,
            )
            if region_result is not None:
                scored_regions.append(region_result)

        if not scored_regions:
            return self._empty_result(
                "no_protocol_candidates",
                noise_floor_db=round(noise_floor, 2),
                active_region_count=len(regions),
            )

        scored_regions.sort(
            key=lambda item: (
                item["top_candidate"]["confidence"],
                item["region_energy_score"],
                item["top_candidate"]["score_raw"],
            ),
            reverse=True,
        )

        best_region = scored_regions[0]
        candidates = best_region["candidates"]

        top = candidates[0]
        second = candidates[1] if len(candidates) > 1 else None

        margin = round(max(top["confidence"] - (second["confidence"] if second else 0.0), 0.0), 2)
        ambiguous = bool(
            second
            and top["confidence"] >= self.STRONG_PROTOCOL_CONFIDENCE
            and margin < self.AMBIGUITY_MARGIN
        )

        readiness = self._readiness_score(
            confidence=top["confidence"],
            evidence_count=len(top["reasons"]),
            ambiguous=ambiguous,
            energy_score=best_region["region_energy_score"],
        )

        decision_state = self._decision_state(
            confidence=top["confidence"],
            readiness=readiness,
            ambiguous=ambiguous,
        )

        explanation_parts = [
            f"primary={top['protocol']}({top['confidence']:.2f})",
            f"family={top['family']}",
            f"state={decision_state}",
            f"freq={top['freq_mhz']:.3f}MHz",
            f"bw={top['bandwidth_mhz']:.3f}MHz",
        ]
        if top["reasons"]:
            explanation_parts.append("evidence=" + ",".join(top["reasons"][:6]))
        if top["penalties"]:
            explanation_parts.append("penalties=" + ",".join(top["penalties"][:4]))
        if ambiguous and second:
            explanation_parts.append(f"contested_with={second['protocol']}({second['confidence']:.2f})")

        return {
            "rf_wideband_candidates": candidates,
            "rf_protocol_candidates": candidates,
            "rf_protocol_evidence": top["reasons"][:10],
            "rf_protocol_penalties": top["penalties"][:10],
            "rf_protocol_ambiguous": ambiguous,
            "rf_protocol_margin": margin,
            "rf_protocol_readiness_score": readiness,
            "rf_protocol_decision_state": decision_state,
            "rf_protocol_explanation": " | ".join(explanation_parts),

            "rf_noise_floor_db": round(noise_floor, 2),
            "rf_active_region_count": len(regions),
            "rf_detection_stage": "wideband",
            "rf_detector_version": self.VERSION,
        }

    # ------------------------------------------------------------------
    # REGION SCORING
    # ------------------------------------------------------------------

    def _score_region(
        self,
        *,
        values: np.ndarray,
        start: int,
        end: int,
        center_freq_hz: float,
        sample_rate_hz: float,
        noise_floor_db: float,
    ) -> Optional[Dict[str, Any]]:
        if end <= start:
            return None

        bin_width_hz = float(sample_rate_hz) / float(len(values))
        start_freq_hz = center_freq_hz + ((start - len(values) / 2.0) * bin_width_hz)
        end_freq_hz = center_freq_hz + (((end - 1) - len(values) / 2.0) * bin_width_hz)

        region_bandwidth_hz = max((end - start) * bin_width_hz, 0.0)
        region_center_hz = (start_freq_hz + end_freq_hz) / 2.0

        freq_mhz = region_center_hz / 1e6
        bandwidth_mhz = region_bandwidth_hz / 1e6
        band = self._detect_band(freq_mhz)

        region_slice = values[start:end]
        if region_slice.size == 0:
            return None

        peak_db = float(np.max(region_slice))
        median_db = float(np.median(region_slice))
        snr_like = max(median_db - noise_floor_db, 0.0)

        energy_score = self._clamp((snr_like / 20.0), 0.0, 1.0)

        candidates = [
            self._score_wifi(freq_mhz, bandwidth_mhz, band, snr_like),
            self._score_ble(freq_mhz, bandwidth_mhz, band, snr_like),
            self._score_zigbee(freq_mhz, bandwidth_mhz, band, snr_like),
            self._score_unknown_wideband(freq_mhz, bandwidth_mhz, band, snr_like),
        ]

        candidates = [
            c for c in candidates
            if c["confidence"] >= self.MIN_PROTOCOL_CONFIDENCE
        ]
        candidates.sort(key=lambda item: (item["confidence"], item["score_raw"]), reverse=True)

        if not candidates:
            return None

        for candidate in candidates:
            candidate["freq_mhz"] = round(freq_mhz, 3)
            candidate["bandwidth_mhz"] = round(bandwidth_mhz, 3)
            candidate["noise_floor_db"] = round(noise_floor_db, 2)
            candidate["signal_peak_db"] = round(peak_db, 2)
            candidate["signal_median_db"] = round(median_db, 2)
            candidate["signal_snr_like_db"] = round(snr_like, 2)

        return {
            "region_start_bin": start,
            "region_end_bin": end,
            "region_center_mhz": round(freq_mhz, 3),
            "region_bandwidth_mhz": round(bandwidth_mhz, 3),
            "region_energy_score": round(float(energy_score), 2),
            "top_candidate": candidates[0],
            "candidates": candidates[:6],
        }

    # ------------------------------------------------------------------
    # PROTOCOL SCORERS
    # ------------------------------------------------------------------

    def _score_wifi(
        self,
        freq_mhz: float,
        bandwidth_mhz: float,
        band: str,
        snr_like: float,
    ) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []
        penalties: List[str] = []

        prox24 = self._grid_proximity(freq_mhz, self.WIFI_24_CHANNELS_MHZ, 3.0)
        prox5 = self._grid_proximity(freq_mhz, self.WIFI_5_CHANNELS_MHZ, 10.0)
        proximity = max(prox24, prox5)

        if proximity > 0.0:
            score += 0.24 * proximity
            reasons.append("wifi_channel_center_proximity")

        if band in {"2.4ghz", "5ghz"}:
            score += 0.10
            reasons.append(f"{band}_wifi_band")

        if 12.0 <= bandwidth_mhz <= 26.0:
            score += 0.28
            reasons.append("wifi_like_bandwidth")
        elif 8.0 <= bandwidth_mhz < 12.0:
            score += 0.12
            reasons.append("possibly_fragmented_wifi_bandwidth")
        elif bandwidth_mhz < 4.0:
            score -= 0.12
            penalties.append("bandwidth_too_narrow_for_wifi")

        if snr_like >= 8.0:
            score += 0.08
            reasons.append("usable_energy_contrast")

        return self._candidate("WiFi", "IEEE 802.11", score, reasons, penalties)

    def _score_ble(
        self,
        freq_mhz: float,
        bandwidth_mhz: float,
        band: str,
        snr_like: float,
    ) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []
        penalties: List[str] = []

        proximity = self._grid_proximity(freq_mhz, self.BLE_ADV_CHANNELS_MHZ, 2.0)
        if proximity > 0.0:
            score += 0.22 * proximity
            reasons.append("ble_adv_channel_proximity")

        if band == "2.4ghz":
            score += 0.08
            reasons.append("2_4ghz_band")

        if 0.7 <= bandwidth_mhz <= 1.5:
            score += 0.28
            reasons.append("ble_like_bandwidth")
        elif bandwidth_mhz > 4.0:
            score -= 0.10
            penalties.append("bandwidth_too_wide_for_ble")

        if snr_like >= 6.0:
            score += 0.05
            reasons.append("detectable_energy_contrast")

        return self._candidate("BLE", "Bluetooth Low Energy", score, reasons, penalties)

    def _score_zigbee(
        self,
        freq_mhz: float,
        bandwidth_mhz: float,
        band: str,
        snr_like: float,
    ) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []
        penalties: List[str] = []

        proximity = self._grid_proximity(freq_mhz, self.ZIGBEE_CHANNELS_MHZ, 2.0)
        if proximity > 0.0:
            score += 0.22 * proximity
            reasons.append("zigbee_channel_proximity")

        if band == "2.4ghz":
            score += 0.08
            reasons.append("2_4ghz_band")

        if 1.5 <= bandwidth_mhz <= 3.2:
            score += 0.28
            reasons.append("zigbee_like_bandwidth")
        elif bandwidth_mhz >= 8.0:
            score -= 0.10
            penalties.append("bandwidth_too_wide_for_zigbee")

        if snr_like >= 6.0:
            score += 0.05
            reasons.append("detectable_energy_contrast")

        return self._candidate("Zigbee", "IEEE 802.15.4", score, reasons, penalties)

    def _score_unknown_wideband(
        self,
        freq_mhz: float,
        bandwidth_mhz: float,
        band: str,
        snr_like: float,
    ) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []
        penalties: List[str] = []

        if bandwidth_mhz >= 5.0:
            score += 0.20
            reasons.append("wideband_energy_region")

        if band in {"2.4ghz", "5ghz", "subghz"}:
            score += 0.05
            reasons.append(f"{band}_spectrum_context")
        else:
            penalties.append("unknown_band_context")

        if snr_like >= 6.0:
            score += 0.06
            reasons.append("usable_energy_contrast")

        return self._candidate("Wideband RF", "Unknown Wideband", score, reasons, penalties, cap=0.78)

    # ------------------------------------------------------------------
    # REGION EXTRACTION
    # ------------------------------------------------------------------

    def _regions(self, mask: np.ndarray) -> List[Tuple[int, int]]:
        regions: List[Tuple[int, int]] = []
        start = None

        for i, active in enumerate(mask):
            if active and start is None:
                start = i
            elif not active and start is not None:
                regions.append((start, i))
                start = None

        if start is not None:
            regions.append((start, len(mask)))

        return regions

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _candidate(
        self,
        protocol: str,
        family: str,
        score: float,
        reasons: List[str],
        penalties: List[str],
        cap: float = 0.98,
    ) -> Dict[str, Any]:
        confidence = round(self._clamp(score, 0.0, cap), 2)
        return {
            "protocol": protocol,
            "family": family,
            "confidence": confidence,
            "score_raw": round(score, 4),
            "reasons": reasons[:10],
            "penalties": penalties[:10],
        }

    def _grid_proximity(
        self,
        freq_mhz: float,
        grid: List[float],
        tolerance_mhz: float,
    ) -> float:
        best = 0.0
        for ref in grid:
            delta = abs(freq_mhz - ref)
            if delta <= tolerance_mhz:
                score = 1.0 - (delta / tolerance_mhz)
                if score > best:
                    best = score
        return round(best, 3)

    def _readiness_score(
        self,
        *,
        confidence: float,
        evidence_count: int,
        ambiguous: bool,
        energy_score: float,
    ) -> float:
        score = (
            (confidence * 0.55)
            + (min(evidence_count, 6) / 6.0) * 0.20
            + (energy_score * 0.25)
        )
        if ambiguous:
            score -= 0.08
        return round(self._clamp(score, 0.0, 1.0), 2)

    def _decision_state(
        self,
        *,
        confidence: float,
        readiness: float,
        ambiguous: bool,
    ) -> str:
        if confidence < 0.28 or readiness < 0.30:
            return "low_observability"
        if ambiguous:
            return "contested"
        if confidence >= 0.72 and readiness >= 0.66:
            return "stable"
        return "provisional"

    def _detect_band(self, freq_mhz: float) -> str:
        if 2400.0 <= freq_mhz <= 2485.0:
            return "2.4ghz"
        if 4900.0 <= freq_mhz <= 5900.0:
            return "5ghz"
        if 300.0 <= freq_mhz <= 928.0:
            return "subghz"
        return "unknown"

    def _empty_result(
        self,
        explanation: str,
        *,
        noise_floor_db: Optional[float] = None,
        active_region_count: int = 0,
    ) -> Dict[str, Any]:
        return {
            "rf_wideband_candidates": [],
            "rf_protocol_candidates": [],
            "rf_protocol_evidence": [],
            "rf_protocol_penalties": [],
            "rf_protocol_ambiguous": False,
            "rf_protocol_margin": 0.0,
            "rf_protocol_readiness_score": 0.0,
            "rf_protocol_decision_state": "low_observability",
            "rf_protocol_explanation": explanation,
            "rf_noise_floor_db": noise_floor_db,
            "rf_active_region_count": active_region_count,
            "rf_detection_stage": "wideband",
            "rf_detector_version": self.VERSION,
        }

    def _clamp(self, value: float, low: float, high: float) -> float:
        return max(low, min(high, value))
