# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF FEATURE EXTRACTION ENGINE
# FILE:         backend/recon/features/feature_extractor.py
#
# VERSION:      v16.0.0 (PHASE-3/4 CLASSIFIER-READINESS FEATURE ENGINE)
# UPDATED:      2026-03-16
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a production-grade RF reconnaissance, emitter analysis, and
# device-intelligence platform built for red-team and SIGINT-style passive RF
# operations.
#
# This module transforms raw or semi-processed emitter observations into a
# stable RF intelligence feature vector that downstream systems can use for:
#
# • protocol classification
# • protocol fingerprinting
# • device fusion
# • hardware / physical fingerprinting
# • behavioral intelligence
# • vendor / product inference
#
# The extractor is not a generic DSP helper.
# It is a classifier-readiness and RF morphology normalization layer.
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# PeakDetector
#     ↓
# EmitterCluster
#     ↓
# RFEmitterTracker
#     ↓
# RFEmitterLifecycleManager
#     ↓
# BurstDetector
#     ↓
# FeatureExtractor                 ← THIS MODULE
#     ↓
# RFProtocolFingerprintEngine
#     ↓
# RFProtocolClassifier
#     ↓
# DeviceFusion / Device Intelligence / Identity Engines
#     ↓
# Red-Team Surface Analysis
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. REAL-TIME SAFE
# -----------------------------------------------------------------------------
# Extraction must remain lightweight enough for continuous passive SDR
# operation without introducing pipeline instability.
#
# 2. DETERMINISTIC OUTPUT
# -----------------------------------------------------------------------------
# The same emitter input should produce the same normalized feature set.
#
# 3. DEFENSIVE NORMALIZATION
# -----------------------------------------------------------------------------
# The extractor must tolerate missing keys, malformed values, NaN / inf,
# empty arrays, alternate field names, and metadata-only operation.
#
# 4. SCHEMA STABILITY
# -----------------------------------------------------------------------------
# Output uses a stable rf_* schema so downstream protocol, identity, API, and
# persistence layers can consume it reliably.
#
# 5. RF INTELLIGENCE FIRST
# -----------------------------------------------------------------------------
# Extracted features must directly help downstream decisions, not merely expose
# generic spectral statistics.
#
# 6. MORPHOLOGY + CLASSIFIER READINESS
# -----------------------------------------------------------------------------
# Feature extraction captures spectral shape, occupancy, burst behavior,
# channel-family proximity, stability, and decision readiness.
#
# 7. COMPATIBILITY PRESERVING
# -----------------------------------------------------------------------------
# Existing GhostRecon modules may still rely on older names. This module
# preserves compatible aliases while standardizing canonical rf_* outputs.
#
# 8. SPARSE-MODE RESILIENCE
# -----------------------------------------------------------------------------
# The extractor must still produce useful intelligence when only metadata,
# tracker state, or burst summaries are available.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# FeatureExtractor IS responsible for:
#
# • schema normalization
# • metadata normalization
# • burst feature derivation
# • spectrum morphology extraction
# • bandwidth estimation
# • band / channel inference
# • channel-family distance estimation
# • OFDM-likelihood estimation
# • modulation-hint estimation
# • signal-class estimation
# • burstiness / compactness / centeredness scoring
# • sub-GHz profile hinting
# • spectral / metadata / burst completeness scoring
# • classifier-readiness scoring
#
# FeatureExtractor is NOT responsible for:
#
# • final protocol classification
# • protocol policy decisions
# • emitter tracking lifecycle
# • SDR control
# • device or vendor identification
# • attack generation
#
# =============================================================================

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np


class FeatureExtractor:
    VERSION = "16.0.0"

    WIFI_CHANNELS = {
        2412: 1,
        2417: 2,
        2422: 3,
        2427: 4,
        2432: 5,
        2437: 6,
        2442: 7,
        2447: 8,
        2452: 9,
        2457: 10,
        2462: 11,
        2467: 12,
        2472: 13,
        2484: 14,
    }

    BLE_ADV_CHANNELS = [2402.0, 2426.0, 2480.0]
    ZIGBEE_CHANNELS = [
        2405.0, 2410.0, 2415.0, 2420.0, 2425.0,
        2430.0, 2435.0, 2440.0, 2445.0, 2450.0,
        2455.0, 2460.0, 2465.0, 2470.0, 2475.0,
    ]

    def __init__(self) -> None:
        self.logger = logging.getLogger("ghostrecon.features")

    # -------------------------------------------------------------------------
    # MAIN EXTRACTION API
    # -------------------------------------------------------------------------

    def extract(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract a normalized RF intelligence feature dictionary from an emitter.

        Returns features only. Caller may merge them into the emitter:
            emitter.update(extractor.extract(emitter))
        """
        features: Dict[str, Any] = {}

        # ---------------------------------------------------------------------
        # CORE METADATA NORMALIZATION
        # ---------------------------------------------------------------------

        freq = self._first(emitter, "rf_frequency_mhz", "freq_mhz", "frequency_mhz")
        power = self._first(emitter, "rf_power_db", "power_db")
        bandwidth = self._first(emitter, "rf_bandwidth_mhz", "bandwidth_mhz")

        features["rf_frequency_mhz"] = self._safe_float(freq)
        features["rf_power_db"] = self._safe_float(power)
        features["rf_bandwidth_mhz"] = self._safe_float(bandwidth, default=0.0)

        # ---------------------------------------------------------------------
        # BAND / CHANNEL / PROXIMITY
        # ---------------------------------------------------------------------

        features["rf_band"] = self._infer_band(features["rf_frequency_mhz"])
        features["rf_channel"] = self._infer_wifi_channel(features["rf_frequency_mhz"])

        wifi_freq, wifi_channel, wifi_dist = self._nearest_channel_info(
            features["rf_frequency_mhz"],
            [(float(k), int(v)) for k, v in self.WIFI_CHANNELS.items()],
        )
        features["rf_nearest_wifi_freq_mhz"] = wifi_freq
        features["rf_nearest_wifi_channel"] = wifi_channel
        features["rf_wifi_channel_distance_mhz"] = wifi_dist

        features["rf_ble_adv_distance_mhz"] = self._nearest_distance(
            features["rf_frequency_mhz"],
            self.BLE_ADV_CHANNELS,
        )
        features["rf_zigbee_channel_distance_mhz"] = self._nearest_distance(
            features["rf_frequency_mhz"],
            self.ZIGBEE_CHANNELS,
        )
        features["rf_channel_distance_mhz"] = features["rf_wifi_channel_distance_mhz"]
        features["rf_nearest_channel_family"] = self._infer_nearest_channel_family(
            wifi_dist=features["rf_wifi_channel_distance_mhz"],
            ble_dist=features["rf_ble_adv_distance_mhz"],
            zigbee_dist=features["rf_zigbee_channel_distance_mhz"],
        )

        # ---------------------------------------------------------------------
        # BURST FEATURES
        # ---------------------------------------------------------------------

        burst_duration = self._first(emitter, "burst_duration", "rf_burst_duration")
        burst_frames = self._first(emitter, "burst_frames", "rf_burst_frames")
        burst_periodicity = self._first(emitter, "burst_periodicity", "rf_burst_periodicity")
        burst_type = self._first(emitter, "burst_type", "rf_burst_type")
        burst_confidence = self._first(emitter, "burst_confidence", "rf_burst_confidence")

        features["rf_burst_duration"] = self._safe_float(burst_duration)
        features["rf_burst_frames"] = self._safe_int(burst_frames)
        features["rf_burst_periodicity"] = self._safe_float(burst_periodicity)
        features["rf_burst_type"] = str(burst_type) if burst_type is not None else None
        features["rf_burst_confidence"] = self._safe_float(burst_confidence, default=0.0)

        features["rf_duty_cycle"] = self._compute_duty_cycle(
            features["rf_burst_duration"],
            features["rf_burst_periodicity"],
        )
        features["rf_burstiness_score"] = self._compute_burstiness_score(
            features["rf_burst_duration"],
            features["rf_burst_periodicity"],
            features["rf_burst_frames"],
        )
        features["rf_burst_regularity_score"] = self._compute_burst_regularity_score(
            features["rf_burst_periodicity"],
            features["rf_duty_cycle"],
        )
        features["rf_temporal_profile"] = self._infer_temporal_profile(
            duty_cycle=features["rf_duty_cycle"],
            burstiness=features["rf_burstiness_score"],
            regularity=features["rf_burst_regularity_score"],
            burst_periodicity=features["rf_burst_periodicity"],
        )

        # ---------------------------------------------------------------------
        # TRACKER / STABILITY FEATURES
        # ---------------------------------------------------------------------

        emitter_hits = self._first(emitter, "emitter_hits", "rf_emitter_hits", "hits")
        emitter_conf = self._first(emitter, "emitter_confidence", "rf_emitter_confidence", "confidence")
        emitter_lifetime = self._first(emitter, "emitter_lifetime", "rf_emitter_lifetime")
        emitter_state = self._first(emitter, "emitter_state", "rf_emitter_state")

        freq_variance = self._first(emitter, "rf_frequency_variance", "frequency_variance")
        bw_variance = self._first(emitter, "rf_bandwidth_variance", "bandwidth_variance")
        power_variance = self._first(emitter, "rf_power_variance", "power_variance")
        tracker_stability = self._first(emitter, "rf_tracker_stability", "tracker_stability")
        continuity = self._first(emitter, "rf_identity_continuity_score", "identity_continuity_score")

        features["rf_emitter_hits"] = self._safe_int(emitter_hits, default=0)
        features["rf_emitter_confidence"] = self._safe_float(emitter_conf, default=0.0)
        features["rf_emitter_lifetime"] = self._safe_float(emitter_lifetime, default=0.0)
        features["rf_emitter_state"] = str(emitter_state) if emitter_state is not None else None

        features["rf_frequency_variance"] = self._safe_float(freq_variance, default=0.0)
        features["rf_bandwidth_variance"] = self._safe_float(bw_variance, default=0.0)
        features["rf_power_variance"] = self._safe_float(power_variance, default=0.0)
        features["rf_tracker_stability"] = self._safe_float(tracker_stability, default=0.0)
        features["rf_identity_continuity_score"] = self._safe_float(continuity, default=0.0)

        features["rf_signal_stability"] = self._estimate_signal_stability(
            hits=features["rf_emitter_hits"],
            confidence=features["rf_emitter_confidence"],
            lifetime=features["rf_emitter_lifetime"],
            tracker_stability=features["rf_tracker_stability"],
            continuity=features["rf_identity_continuity_score"],
            freq_variance=features["rf_frequency_variance"],
            bw_variance=features["rf_bandwidth_variance"],
            power_variance=features["rf_power_variance"],
        )

        # ---------------------------------------------------------------------
        # SPECTRUM INPUT
        # ---------------------------------------------------------------------

        spectrum = self._first(
            emitter,
            "fft_magnitude",
            "spectrum",
            "fft_bins",
            "magnitude",
        )

        spectrum_array = self._sanitize_spectrum(spectrum)

        if spectrum_array is None or spectrum_array.size == 0:
            self.logger.debug("Feature extraction in metadata-only mode (no usable spectrum)")
            self._populate_metadata_only_features(features)
            self._finalize_quality_scores(features)
            self._populate_legacy_aliases(features)
            return features

        # ---------------------------------------------------------------------
        # SPECTRUM SETUP
        # ---------------------------------------------------------------------

        power_linear = np.abs(spectrum_array)
        n = int(power_linear.size)

        if n <= 0:
            self._populate_metadata_only_features(features)
            self._finalize_quality_scores(features)
            self._populate_legacy_aliases(features)
            return features

        sample_rate_hz = self._safe_float(
            self._first(emitter, "sample_rate_hz", "sample_rate", "rf_sample_rate_hz"),
            default=20e6,
        )
        bin_width_hz = float(sample_rate_hz / max(n, 1))

        # ---------------------------------------------------------------------
        # BASIC STATISTICS
        # ---------------------------------------------------------------------

        mean_val = float(np.mean(power_linear))
        std_val = float(np.std(power_linear))
        variance = float(np.var(power_linear))
        max_val = float(np.max(power_linear))
        min_val = float(np.min(power_linear))
        median_val = float(np.median(power_linear))

        features["rf_spectral_mean"] = mean_val
        features["rf_spectral_std"] = std_val
        features["rf_spectral_variance"] = variance
        features["rf_spectral_median"] = median_val

        # ---------------------------------------------------------------------
        # ENERGY / RANGE
        # ---------------------------------------------------------------------

        signal_energy = float(np.sum(power_linear))
        power_range = max_val - min_val
        baseline = mean_val + 1e-12
        energy_contrast = signal_energy / (baseline * max(n, 1))

        features["rf_signal_energy"] = signal_energy
        features["rf_power_dynamic_range"] = power_range
        features["rf_energy_contrast_ratio"] = float(energy_contrast)

        # ---------------------------------------------------------------------
        # ENTROPY / FLATNESS / SHAPE
        # ---------------------------------------------------------------------

        total = float(np.sum(power_linear))
        if total > 0.0:
            probs = power_linear / total
            entropy = -np.sum(probs * np.log2(probs + 1e-12))
            features["rf_spectral_entropy"] = float(entropy)
        else:
            features["rf_spectral_entropy"] = 0.0

        geo_mean = float(np.exp(np.mean(np.log(power_linear + 1e-12))))
        ar_mean = float(np.mean(power_linear + 1e-12))
        flatness = float(geo_mean / ar_mean)
        features["rf_spectral_flatness"] = flatness

        if std_val > 0.0:
            kurtosis = np.mean(((power_linear - mean_val) / std_val) ** 4)
            skewness = np.mean(((power_linear - mean_val) / std_val) ** 3)
            features["rf_spectral_kurtosis"] = float(kurtosis)
            features["rf_spectral_skewness"] = float(skewness)
        else:
            features["rf_spectral_kurtosis"] = 0.0
            features["rf_spectral_skewness"] = 0.0

        # ---------------------------------------------------------------------
        # CENTROID / ROLLOFF / CENTEREDNESS
        # ---------------------------------------------------------------------

        indices = np.arange(n, dtype=np.float64)
        centroid_bin = float(np.sum(indices * power_linear) / (signal_energy + 1e-12))
        features["rf_spectral_centroid"] = float(centroid_bin / max(n, 1))

        cumulative = np.cumsum(power_linear)
        if cumulative.size > 0 and cumulative[-1] > 0.0:
            rolloff_threshold = 0.85 * cumulative[-1]
            rolloff_index = int(np.where(cumulative >= rolloff_threshold)[0][0])
            features["rf_spectral_rolloff"] = float(rolloff_index / max(n, 1))
        else:
            features["rf_spectral_rolloff"] = 0.0

        center_bin = (n - 1) / 2.0
        centeredness = 1.0 - min(abs(centroid_bin - center_bin) / max(center_bin, 1.0), 1.0)
        features["rf_centeredness"] = round(float(centeredness), 4)

        # ---------------------------------------------------------------------
        # PEAKS / CARRIERS / OCCUPANCY
        # ---------------------------------------------------------------------

        threshold = mean_val + std_val
        strong_threshold = mean_val + (2.0 * std_val)

        peaks = np.where(power_linear > threshold)[0]
        strong_peaks = np.where(power_linear > strong_threshold)[0]

        peak_density = float(len(peaks) / max(n, 1))
        carrier_count = int(len(strong_peaks))

        features["rf_peak_density"] = peak_density
        features["rf_carrier_count"] = carrier_count
        features["rf_peak_power_ratio"] = float(max_val / (mean_val + 1e-12))
        features["rf_occupancy_ratio"] = peak_density

        top_peak_indices = self._top_k_indices(power_linear, k=min(8, n))
        features["rf_top_peaks_count"] = int(len(top_peak_indices))

        peak_spacing_mean, peak_spacing_std = self._peak_spacing_stats(top_peak_indices)
        features["rf_peak_spacing_mean"] = peak_spacing_mean
        features["rf_peak_spacing_std"] = peak_spacing_std

        features["rf_multicarrier_score"] = self._compute_multicarrier_score(
            carrier_count=carrier_count,
            peak_density=peak_density,
            spacing_std=peak_spacing_std,
            flatness=flatness,
        )
        features["rf_spectral_compactness"] = self._compute_spectral_compactness(
            peak_density=peak_density,
            flatness=flatness,
            bandwidth_mhz=features["rf_bandwidth_mhz"],
        )

        # ---------------------------------------------------------------------
        # BANDWIDTH ESTIMATION
        # ---------------------------------------------------------------------

        active_bins = np.where(power_linear > threshold)[0]
        if len(active_bins) > 0:
            bw_bins = int(max(active_bins) - min(active_bins) + 1)
            bw_norm = bw_bins / max(n, 1)
            bw_hz = float(bw_bins * bin_width_hz)
            bw_mhz = float(bw_hz / 1e6)

            features["rf_bandwidth_estimate"] = float(bw_norm)
            features["rf_bandwidth_hz_estimate"] = bw_hz
            features["rf_bandwidth_mhz_estimate"] = bw_mhz

            if not features["rf_bandwidth_mhz"] or features["rf_bandwidth_mhz"] <= 0.0:
                features["rf_bandwidth_mhz"] = bw_mhz
        else:
            features["rf_bandwidth_estimate"] = 0.0
            features["rf_bandwidth_hz_estimate"] = 0.0
            features["rf_bandwidth_mhz_estimate"] = 0.0

        features["rf_bandwidth_quality"] = self._compute_bandwidth_quality(
            measured_bandwidth_mhz=bandwidth,
            estimated_bandwidth_mhz=features.get("rf_bandwidth_mhz_estimate"),
        )

        # ---------------------------------------------------------------------
        # OFDM / SIGNAL CLASS / MODULATION HINTS
        # ---------------------------------------------------------------------

        ofdm_likelihood = self._compute_ofdm_likelihood(
            carrier_count=carrier_count,
            peak_density=peak_density,
            flatness=flatness,
            bandwidth_mhz=features["rf_bandwidth_mhz"],
            spacing_std=peak_spacing_std,
        )
        features["rf_ofdm_likelihood"] = ofdm_likelihood

        features["rf_signal_class"] = self._infer_signal_class(
            bandwidth_mhz=features["rf_bandwidth_mhz"],
            carrier_count=carrier_count,
            peak_density=peak_density,
            ofdm_likelihood=ofdm_likelihood,
            burstiness_score=features["rf_burstiness_score"],
            compactness=features["rf_spectral_compactness"],
            multicarrier_score=features["rf_multicarrier_score"],
        )

        features["rf_modulation_hint"] = self._infer_modulation_hint(
            carrier_count=carrier_count,
            peak_density=peak_density,
            bandwidth_mhz=features["rf_bandwidth_mhz"],
            ofdm_likelihood=ofdm_likelihood,
            flatness=flatness,
            centeredness=features["rf_centeredness"],
            compactness=features["rf_spectral_compactness"],
            temporal_profile=features["rf_temporal_profile"],
        )
        features["symbol_rate_estimate"] = self._estimate_symbol_rate(
            rf_band=features.get("rf_band"),
            freq_mhz=features.get("rf_frequency_mhz"),
            bandwidth_mhz=features.get("rf_bandwidth_mhz"),
            bandwidth_hz=features.get("rf_bandwidth_hz_estimate"),
            modulation_hint=features.get("rf_modulation_hint"),
            temporal_profile=features.get("rf_temporal_profile"),
        )
        features["rf_symbol_rate_estimate"] = features["symbol_rate_estimate"]

        subghz_frame_hints = self._infer_subghz_frame_hints(
            freq_mhz=features.get("rf_frequency_mhz"),
            rf_band=features.get("rf_band"),
            bandwidth_mhz=features.get("rf_bandwidth_mhz"),
            modulation_hint=features.get("rf_modulation_hint"),
            duty_cycle=features.get("rf_duty_cycle"),
            burst_periodicity=features.get("rf_burst_periodicity"),
            burst_duration=features.get("rf_burst_duration"),
            temporal_profile=features.get("rf_temporal_profile"),
            symbol_rate=features.get("symbol_rate_estimate"),
        )
        for key, value in subghz_frame_hints.items():
            if value is not None:
                features[key] = value

        # ---------------------------------------------------------------------
        # SUB-GHZ PROFILE HINTING
        # ---------------------------------------------------------------------

        features["rf_subghz_profile"] = self._infer_subghz_profile(
            rf_band=features["rf_band"],
            freq_mhz=features.get("rf_frequency_mhz"),
            bandwidth_mhz=features["rf_bandwidth_mhz"],
            modulation_hint=features["rf_modulation_hint"],
            duty_cycle=features["rf_duty_cycle"],
            signal_class=features["rf_signal_class"],
            temporal_profile=features.get("rf_temporal_profile"),
        )

        # ---------------------------------------------------------------------
        # FINAL QUALITY / READINESS
        # ---------------------------------------------------------------------

        self._finalize_quality_scores(features)
        self._populate_legacy_aliases(features)
        return features

    # -------------------------------------------------------------------------
    # CORE HELPERS
    # -------------------------------------------------------------------------

    def _first(self, emitter: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in emitter and emitter.get(key) is not None:
                return emitter.get(key)
        return None

    def _sanitize_spectrum(self, spectrum: Any) -> Optional[np.ndarray]:
        if spectrum is None:
            return None

        try:
            arr = np.asarray(spectrum, dtype=np.float64)
        except Exception:
            return None

        if arr.size == 0:
            return None

        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        arr = np.abs(arr)
        return arr if arr.size > 0 else None

    def _safe_float(self, value: Any, default: Optional[float] = None) -> Optional[float]:
        if value is None:
            return default
        try:
            v = float(value)
            if np.isnan(v) or np.isinf(v):
                return default
            return v
        except Exception:
            return default

    def _safe_int(self, value: Any, default: Optional[int] = None) -> Optional[int]:
        if value is None:
            return default
        try:
            return int(value)
        except Exception:
            return default

    # -------------------------------------------------------------------------
    # BAND / CHANNEL HELPERS
    # -------------------------------------------------------------------------

    def _infer_band(self, freq: Any) -> str:
        f = self._safe_float(freq)
        if f is None:
            return "unknown"
        if 2400.0 <= f <= 2485.0:
            return "2.4ghz"
        if 4900.0 <= f <= 5900.0:
            return "5ghz"
        if f < 1000.0:
            return "subghz"
        return "unknown"

    def _infer_wifi_channel(self, freq: Any) -> Optional[int]:
        f = self._safe_float(freq)
        if f is None:
            return None

        best_channel = None
        best_diff = 999.0
        for ch_freq, ch_num in self.WIFI_CHANNELS.items():
            diff = abs(f - float(ch_freq))
            if diff < best_diff:
                best_diff = diff
                best_channel = ch_num

        return best_channel if best_diff <= 2.5 else None

    def _nearest_channel_info(
        self,
        freq_mhz: Optional[float],
        channels: Sequence[Tuple[float, int]],
    ) -> Tuple[Optional[float], Optional[int], Optional[float]]:
        if freq_mhz is None or not channels:
            return None, None, None

        best_freq = None
        best_channel = None
        best_dist = None

        for ch_freq, ch_num in channels:
            dist = abs(freq_mhz - ch_freq)
            if best_dist is None or dist < best_dist:
                best_freq = ch_freq
                best_channel = ch_num
                best_dist = dist

        return (
            best_freq,
            best_channel,
            round(float(best_dist), 4) if best_dist is not None else None,
        )

    def _nearest_distance(self, freq_mhz: Optional[float], grid: Sequence[float]) -> Optional[float]:
        if freq_mhz is None or not grid:
            return None
        return round(float(min(abs(freq_mhz - x) for x in grid)), 4)

    def _infer_nearest_channel_family(
        self,
        *,
        wifi_dist: Optional[float],
        ble_dist: Optional[float],
        zigbee_dist: Optional[float],
    ) -> str:
        candidates = {
            "wifi": wifi_dist if wifi_dist is not None else 9999.0,
            "ble_adv": ble_dist if ble_dist is not None else 9999.0,
            "zigbee": zigbee_dist if zigbee_dist is not None else 9999.0,
        }
        family = min(candidates, key=candidates.get)
        return family if candidates[family] < 9999.0 else "unknown"

    # -------------------------------------------------------------------------
    # BURST HELPERS
    # -------------------------------------------------------------------------

    def _compute_duty_cycle(
        self,
        burst_duration: Optional[float],
        burst_periodicity: Optional[float],
    ) -> Optional[float]:
        if burst_duration is None or burst_periodicity is None or burst_periodicity <= 0:
            return None
        return float(min(max(burst_duration / burst_periodicity, 0.0), 1.0))

    def _compute_burstiness_score(
        self,
        burst_duration: Optional[float],
        burst_periodicity: Optional[float],
        burst_frames: Optional[int],
    ) -> float:
        score = 0.0

        if burst_duration is not None and burst_duration < 0.020:
            score += 0.30
        elif burst_duration is not None and burst_duration < 0.100:
            score += 0.15

        if burst_periodicity is not None:
            if 0.02 <= burst_periodicity <= 0.50:
                score += 0.25
            elif 0.50 < burst_periodicity <= 2.0:
                score += 0.12

        duty = self._compute_duty_cycle(burst_duration, burst_periodicity)
        if duty is not None:
            if duty < 0.15:
                score += 0.25
            elif duty < 0.35:
                score += 0.12

        if burst_frames is not None:
            if burst_frames <= 3:
                score += 0.20
            elif burst_frames <= 10:
                score += 0.10

        return round(min(score, 1.0), 4)

    def _compute_burst_regularity_score(
        self,
        burst_periodicity: Optional[float],
        duty_cycle: Optional[float],
    ) -> float:
        score = 0.0

        if burst_periodicity is not None:
            if 0.08 <= burst_periodicity <= 0.12:
                score += 0.45
            elif 0.02 <= burst_periodicity <= 1.0:
                score += 0.25

        if duty_cycle is not None:
            if 0.01 <= duty_cycle <= 0.20:
                score += 0.25
            elif duty_cycle <= 0.40:
                score += 0.12

        return round(min(score, 1.0), 4)

    def _infer_temporal_profile(
        self,
        *,
        duty_cycle: Optional[float],
        burstiness: Optional[float],
        regularity: Optional[float],
        burst_periodicity: Optional[float],
    ) -> str:
        duty = duty_cycle if duty_cycle is not None else 1.0
        bursty = burstiness or 0.0
        regular = regularity or 0.0
        period = burst_periodicity

        if bursty >= 0.60 and duty < 0.20:
            return "bursty"
        if regular >= 0.60 and period is not None:
            return "periodic"
        if duty >= 0.70:
            return "continuous"
        if 0.20 <= duty < 0.70:
            return "intermittent"
        return "unknown"

    def _estimate_symbol_rate(
        self,
        *,
        rf_band: Optional[str],
        freq_mhz: Optional[float],
        bandwidth_mhz: Optional[float],
        bandwidth_hz: Optional[float],
        modulation_hint: Optional[str],
        temporal_profile: Optional[str],
    ) -> float:
        if rf_band != "subghz":
            return 0.0

        bw_hz = self._safe_float(bandwidth_hz, default=0.0) or 0.0
        if bw_hz <= 0.0:
            bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0
            bw_hz = bw * 1e6

        if bw_hz <= 0.0:
            return 0.0

        modulation = str(modulation_hint or "").lower()
        temporal = str(temporal_profile or "").lower()
        freq = self._safe_float(freq_mhz, default=0.0) or 0.0
        wmbus_center_like = any(abs(freq - center) <= 0.18 for center in (868.30, 868.95, 869.525))

        if modulation == "lora_like":
            estimate = bw_hz / 4.0
        elif wmbus_center_like and modulation in {"fsk_like", "gfsk_fsk_like", "ook_fsk_like"}:
            estimate = bw_hz / 1.8
        elif modulation in {"fsk_like", "gfsk_fsk_like", "ook_fsk_like"}:
            estimate = bw_hz / 2.2
        else:
            estimate = bw_hz / 3.0

        if temporal in {"periodic", "bursty"} and 6000.0 <= estimate <= 150000.0:
            estimate *= 1.05

        return round(max(0.0, estimate), 2)

    def _infer_subghz_frame_hints(
        self,
        *,
        freq_mhz: Optional[float],
        rf_band: Optional[str],
        bandwidth_mhz: Optional[float],
        modulation_hint: Optional[str],
        duty_cycle: Optional[float],
        burst_periodicity: Optional[float],
        burst_duration: Optional[float],
        temporal_profile: Optional[str],
        symbol_rate: Optional[float],
    ) -> Dict[str, Any]:
        if rf_band != "subghz":
            return {}

        freq = self._safe_float(freq_mhz, default=0.0) or 0.0
        bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0
        mod = str(modulation_hint or "").lower()
        temporal = str(temporal_profile or "").lower()
        sym = self._safe_float(symbol_rate, default=0.0) or 0.0
        duty = self._safe_float(duty_cycle, default=None)
        period = self._safe_float(burst_periodicity, default=None)
        duration = self._safe_float(burst_duration, default=None)

        wmbus_center_like = any(abs(freq - center) <= 0.18 for center in (868.30, 868.95, 869.525))
        narrow_metering = 0.004 <= bw <= 0.12
        periodic_like = temporal in {"periodic", "bursty"} or (period is not None and 0.02 <= period <= 4.0)
        low_duty = duty is not None and duty <= 0.35
        short_burst = duration is not None and duration <= 0.25

        if (
            wmbus_center_like
            and narrow_metering
            and mod in {"fsk_like", "gfsk_fsk_like", "ook_fsk_like"}
            and periodic_like
            and (low_duty or short_burst)
            and 4000.0 <= sym <= 120000.0
        ):
            return {
                "rf_frame_structure": "metering_burst",
                "rf_frame_protocol_hint": "WirelessMbus",
                "rf_frame_confidence": 0.58,
                "rf_subghz_profile": "wireless_mbus_like",
            }

        return {}

    # -------------------------------------------------------------------------
    # STABILITY HELPERS
    # -------------------------------------------------------------------------

    def _estimate_signal_stability(
        self,
        *,
        hits: Optional[int],
        confidence: Optional[float],
        lifetime: Optional[float],
        tracker_stability: Optional[float],
        continuity: Optional[float],
        freq_variance: Optional[float],
        bw_variance: Optional[float],
        power_variance: Optional[float],
    ) -> float:
        hit_score = min((hits or 0) / 10.0, 1.0)
        conf_score = min((confidence or 0.0), 1.0)
        life_score = min((lifetime or 0.0) / 5.0, 1.0)
        tracker_score = min((tracker_stability or 0.0), 1.0)
        continuity_score = min((continuity or 0.0), 1.0)

        penalty = 0.0
        if freq_variance is not None and freq_variance > 3.0:
            penalty += 0.08
        elif freq_variance is not None and freq_variance > 1.0:
            penalty += 0.04

        if bw_variance is not None and bw_variance > 3.0:
            penalty += 0.05
        elif bw_variance is not None and bw_variance > 1.0:
            penalty += 0.02

        if power_variance is not None and power_variance > 12.0:
            penalty += 0.05
        elif power_variance is not None and power_variance > 6.0:
            penalty += 0.02

        score = (
            (hit_score * 0.25) +
            (conf_score * 0.25) +
            (life_score * 0.15) +
            (tracker_score * 0.20) +
            (continuity_score * 0.15)
        ) - penalty

        return round(max(min(score, 1.0), 0.0), 4)

    # -------------------------------------------------------------------------
    # PEAK / SPACING HELPERS
    # -------------------------------------------------------------------------

    def _top_k_indices(self, values: np.ndarray, k: int) -> List[int]:
        if values.size == 0 or k <= 0:
            return []
        idx = np.argpartition(values, -k)[-k:]
        idx = idx[np.argsort(values[idx])[::-1]]
        return [int(i) for i in idx.tolist()]

    def _peak_spacing_stats(self, indices: Sequence[int]) -> Tuple[float, float]:
        if len(indices) < 2:
            return 0.0, 0.0

        ordered = sorted(indices)
        spacings = np.diff(np.asarray(ordered, dtype=np.float64))
        if spacings.size == 0:
            return 0.0, 0.0

        return round(float(np.mean(spacings)), 4), round(float(np.std(spacings)), 4)

    # -------------------------------------------------------------------------
    # DERIVED RF INTELLIGENCE
    # -------------------------------------------------------------------------

    def _compute_spectral_compactness(
        self,
        *,
        peak_density: Optional[float],
        flatness: Optional[float],
        bandwidth_mhz: Optional[float],
    ) -> float:
        pd = peak_density or 0.0
        fl = flatness or 0.0
        bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0

        score = 0.0

        if pd < 0.05:
            score += 0.40
        elif pd < 0.12:
            score += 0.25

        if fl < 0.35:
            score += 0.30
        elif fl < 0.55:
            score += 0.15

        if 0.0 < bw < 1.0:
            score += 0.20
        elif bw < 3.0:
            score += 0.10

        return round(min(score, 1.0), 4)

    def _compute_bandwidth_quality(
        self,
        *,
        measured_bandwidth_mhz: Optional[float],
        estimated_bandwidth_mhz: Optional[float],
    ) -> float:
        measured = self._safe_float(measured_bandwidth_mhz)
        estimated = self._safe_float(estimated_bandwidth_mhz)

        if estimated is None or estimated <= 0:
            return 0.0
        if measured is None or measured <= 0:
            return 0.5

        delta = abs(measured - estimated)
        rel = delta / max(estimated, 1e-6)

        if rel <= 0.15:
            return 1.0
        if rel <= 0.35:
            return 0.75
        if rel <= 0.60:
            return 0.45
        return 0.20

    def _compute_multicarrier_score(
        self,
        *,
        carrier_count: Optional[int],
        peak_density: Optional[float],
        spacing_std: Optional[float],
        flatness: Optional[float],
    ) -> float:
        cc = carrier_count or 0
        pd = peak_density or 0.0
        sstd = spacing_std or 0.0
        fl = flatness or 0.0

        score = 0.0

        if cc >= 10:
            score += 0.35
        elif cc >= 6:
            score += 0.20

        if pd >= 0.08:
            score += 0.20
        elif pd >= 0.04:
            score += 0.10

        if 0.0 < sstd <= 5.0:
            score += 0.25
        elif sstd <= 10.0:
            score += 0.12

        if fl >= 0.45:
            score += 0.15

        return round(min(score, 1.0), 4)

    def _compute_ofdm_likelihood(
        self,
        *,
        carrier_count: Optional[int],
        peak_density: Optional[float],
        flatness: Optional[float],
        bandwidth_mhz: Optional[float],
        spacing_std: Optional[float],
    ) -> float:
        cc = carrier_count or 0
        pd = peak_density or 0.0
        fl = flatness or 0.0
        bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0
        sstd = spacing_std or 0.0

        score = 0.0

        if cc >= 20:
            score += 0.35
        elif cc >= 10:
            score += 0.20

        if pd >= 0.15:
            score += 0.20
        elif pd >= 0.08:
            score += 0.10

        if fl >= 0.60:
            score += 0.18
        elif fl >= 0.40:
            score += 0.09

        if bw >= 8.0:
            score += 0.17
        elif bw >= 4.0:
            score += 0.08

        if cc >= 6:
            if 0.0 < sstd <= 5.0:
                score += 0.10
            elif sstd <= 10.0:
                score += 0.05

        return round(min(score, 1.0), 4)

    def _infer_signal_class(
        self,
        *,
        bandwidth_mhz: Optional[float],
        carrier_count: Optional[int],
        peak_density: Optional[float],
        ofdm_likelihood: Optional[float],
        burstiness_score: Optional[float],
        compactness: Optional[float],
        multicarrier_score: Optional[float],
    ) -> str:
        bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0
        cc = carrier_count or 0
        pd = peak_density or 0.0
        ofdm = ofdm_likelihood or 0.0
        bursty = burstiness_score or 0.0
        compact = compactness or 0.0
        multi = multicarrier_score or 0.0

        if ofdm >= 0.60 or (bw >= 8.0 and cc >= 10):
            return "wideband"

        if multi >= 0.55 or (cc >= 8 and pd >= 0.10):
            return "multicarrier"

        if bursty >= 0.65 and bw < 1.0:
            return "bursty"

        if 1.0 <= bw <= 8.0:
            return "packet_radio"

        if 0.0 < bw < 1.0 and compact >= 0.35 and pd < 0.12:
            return "narrowband"

        return "unknown"

    def _infer_modulation_hint(
        self,
        *,
        carrier_count: Optional[int],
        peak_density: Optional[float],
        bandwidth_mhz: Optional[float],
        ofdm_likelihood: Optional[float],
        flatness: Optional[float],
        centeredness: Optional[float],
        compactness: Optional[float],
        temporal_profile: Optional[str],
    ) -> str:
        cc = carrier_count or 0
        pd = peak_density or 0.0
        bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0
        ofdm = ofdm_likelihood or 0.0
        fl = flatness or 0.0
        cent = centeredness or 0.0
        compact = compactness or 0.0
        temporal = temporal_profile or "unknown"

        if ofdm >= 0.60:
            return "ofdm_like"

        if bw <= 0.60 and fl >= 0.50 and cent >= 0.50:
            return "lora_like"

        if bw < 0.25 and cc <= 3 and compact >= 0.35:
            return "ook_fsk_like"

        if 0.25 <= bw <= 2.5 and cc <= 6 and pd < 0.08:
            return "gfsk_fsk_like"

        if cc >= 8 and pd >= 0.10:
            return "multicarrier"

        if temporal == "bursty" and bw < 0.30:
            return "ook_fsk_like"

        return "unknown"

    def _infer_subghz_profile(
        self,
        *,
        rf_band: Optional[str],
        freq_mhz: Optional[float],
        bandwidth_mhz: Optional[float],
        modulation_hint: Optional[str],
        duty_cycle: Optional[float],
        signal_class: Optional[str],
        temporal_profile: Optional[str],
    ) -> Optional[str]:
        if rf_band != "subghz":
            return None

        bw = self._safe_float(bandwidth_mhz, default=0.0) or 0.0
        freq = self._safe_float(freq_mhz, default=0.0) or 0.0
        mod = str(modulation_hint or "")
        duty = duty_cycle if duty_cycle is not None else None
        sigcls = str(signal_class or "")
        temporal = str(temporal_profile or "").lower()
        wmbus_centers = (868.30, 868.95, 869.525)
        wmbus_aligned = any(abs(freq - center) <= 0.18 for center in wmbus_centers)
        narrow_periodic_fsk = (
            wmbus_aligned
            and 0.004 <= bw <= 0.25
            and mod in {"gfsk_fsk_like", "ook_fsk_like", "fsk_like"}
            and (
                (duty is not None and duty <= 0.30)
                or temporal in {"periodic", "bursty", "regular"}
            )
        )

        if mod == "lora_like":
            return "lpwan_lora_like"

        if narrow_periodic_fsk:
            return "wireless_mbus_like"

        if mod == "ook_fsk_like" and bw < 0.30:
            return "remote_control_like"

        if mod == "gfsk_fsk_like" and 0.20 <= bw <= 1.5:
            return "telemetry_fsk_like"

        if sigcls == "bursty" and duty is not None and duty < 0.15 and bw < 0.50:
            return "bursty_control_like"

        if bw < 0.50:
            return "narrow_subghz_like"

        return "generic_subghz"

    # -------------------------------------------------------------------------
    # METADATA-ONLY FALLBACK
    # -------------------------------------------------------------------------

    def _populate_metadata_only_features(self, features: Dict[str, Any]) -> None:
        bw = self._safe_float(features.get("rf_bandwidth_mhz"), default=0.0) or 0.0

        features["rf_spectral_mean"] = 0.0
        features["rf_spectral_std"] = 0.0
        features["rf_spectral_variance"] = 0.0
        features["rf_spectral_median"] = 0.0
        features["rf_signal_energy"] = 0.0
        features["rf_power_dynamic_range"] = 0.0
        features["rf_energy_contrast_ratio"] = 0.0
        features["rf_spectral_entropy"] = 0.0
        features["rf_spectral_flatness"] = 0.0
        features["rf_spectral_kurtosis"] = 0.0
        features["rf_spectral_skewness"] = 0.0
        features["rf_spectral_centroid"] = 0.0
        features["rf_spectral_rolloff"] = 0.0
        features["rf_centeredness"] = 0.0
        features["rf_peak_density"] = 0.0
        features["rf_carrier_count"] = 0
        features["rf_peak_power_ratio"] = 0.0
        features["rf_top_peaks_count"] = 0
        features["rf_peak_spacing_mean"] = 0.0
        features["rf_peak_spacing_std"] = 0.0
        features["rf_multicarrier_score"] = 0.0
        features["rf_bandwidth_estimate"] = 0.0
        features["rf_bandwidth_hz_estimate"] = 0.0
        features["rf_bandwidth_mhz_estimate"] = 0.0
        features["rf_bandwidth_quality"] = 0.0
        features["rf_spectral_compactness"] = 0.0
        features["rf_occupancy_ratio"] = 0.0

        features["rf_temporal_profile"] = self._infer_temporal_profile(
            duty_cycle=features.get("rf_duty_cycle"),
            burstiness=features.get("rf_burstiness_score"),
            regularity=features.get("rf_burst_regularity_score"),
            burst_periodicity=features.get("rf_burst_periodicity"),
        )

        features["rf_ofdm_likelihood"] = 0.0
        features["rf_signal_class"] = self._infer_signal_class(
            bandwidth_mhz=bw,
            carrier_count=0,
            peak_density=0.0,
            ofdm_likelihood=0.0,
            burstiness_score=features.get("rf_burstiness_score"),
            compactness=0.0,
            multicarrier_score=0.0,
        )
        features["rf_modulation_hint"] = self._infer_modulation_hint(
            carrier_count=0,
            peak_density=0.0,
            bandwidth_mhz=bw,
            ofdm_likelihood=0.0,
            flatness=0.0,
            centeredness=0.0,
            compactness=0.0,
            temporal_profile=features.get("rf_temporal_profile"),
        )
        features["rf_subghz_profile"] = self._infer_subghz_profile(
            rf_band=features.get("rf_band"),
            freq_mhz=features.get("rf_frequency_mhz"),
            bandwidth_mhz=bw,
            modulation_hint=features.get("rf_modulation_hint"),
            duty_cycle=features.get("rf_duty_cycle"),
            signal_class=features.get("rf_signal_class"),
            temporal_profile=features.get("rf_temporal_profile"),
        )

    # -------------------------------------------------------------------------
    # FINAL QUALITY / READINESS
    # -------------------------------------------------------------------------

    def _finalize_quality_scores(self, features: Dict[str, Any]) -> None:
        metadata_keys = [
            "rf_frequency_mhz",
            "rf_power_db",
            "rf_bandwidth_mhz",
            "rf_band",
            "rf_emitter_hits",
            "rf_emitter_confidence",
            "rf_signal_stability",
        ]
        burst_keys = [
            "rf_burst_duration",
            "rf_burst_periodicity",
            "rf_burst_frames",
            "rf_burstiness_score",
            "rf_burst_regularity_score",
            "rf_temporal_profile",
        ]
        spectral_keys = [
            "rf_peak_density",
            "rf_carrier_count",
            "rf_spectral_entropy",
            "rf_spectral_flatness",
            "rf_spectral_compactness",
            "rf_ofdm_likelihood",
            "rf_bandwidth_mhz_estimate",
        ]
        decision_keys = [
            "rf_signal_class",
            "rf_modulation_hint",
            "rf_nearest_channel_family",
            "rf_subghz_profile",
        ]

        features["rf_metadata_completeness"] = self._completeness_ratio(features, metadata_keys)
        features["rf_burst_completeness"] = self._completeness_ratio(features, burst_keys)
        features["rf_spectral_completeness"] = self._completeness_ratio(features, spectral_keys)
        features["rf_decision_completeness"] = self._completeness_ratio(features, decision_keys)

        total = (
            (features["rf_metadata_completeness"] * 0.35) +
            (features["rf_burst_completeness"] * 0.20) +
            (features["rf_spectral_completeness"] * 0.30) +
            (features["rf_decision_completeness"] * 0.15)
        )
        features["rf_feature_completeness"] = round(min(max(total, 0.0), 1.0), 4)

        readiness = 0.0
        readiness += 0.20 * min(features.get("rf_feature_completeness", 0.0), 1.0)
        readiness += 0.20 * min(features.get("rf_signal_stability", 0.0), 1.0)
        readiness += 0.12 * min(features.get("rf_bandwidth_quality", 0.0), 1.0)
        readiness += 0.10 * min(features.get("rf_burstiness_score", 0.0), 1.0)
        readiness += 0.08 * min(features.get("rf_burst_regularity_score", 0.0), 1.0)
        readiness += 0.10 * min(features.get("rf_spectral_completeness", 0.0), 1.0)
        readiness += 0.10 * min(features.get("rf_metadata_completeness", 0.0), 1.0)

        if features.get("rf_signal_class") not in (None, "", "unknown"):
            readiness += 0.04
        if features.get("rf_modulation_hint") not in (None, "", "unknown"):
            readiness += 0.04
        if (features.get("rf_peak_density", 0.0) or 0.0) > 0.0:
            readiness += 0.02

        features["rf_classifier_readiness"] = round(min(readiness, 1.0), 4)

    def _completeness_ratio(self, features: Dict[str, Any], keys: Sequence[str]) -> float:
        if not keys:
            return 0.0

        present = 0
        for key in keys:
            value = features.get(key)
            if value is None:
                continue
            if isinstance(value, str) and value.strip() == "":
                continue
            if isinstance(value, str) and value.lower() == "unknown":
                continue
            if isinstance(value, (int, float)) and value == 0:
                continue
            present += 1

        return round(float(present / max(len(keys), 1)), 4)

    # -------------------------------------------------------------------------
    # LEGACY COMPATIBILITY
    # -------------------------------------------------------------------------

    def _populate_legacy_aliases(self, features: Dict[str, Any]) -> None:
        features["rf_bandwidth_est_mhz"] = features.get("rf_bandwidth_mhz_estimate")
        features["rf_protocol_readiness"] = features.get("rf_classifier_readiness")

        features["band"] = features.get("rf_band")
        features["channel"] = features.get("rf_channel")
        features["protocol_readiness"] = features.get("rf_classifier_readiness")
        features["modulation"] = features.get("rf_modulation_hint")
        features["signal_class"] = features.get("rf_signal_class")
        features["bandwidth_mhz"] = features.get("rf_bandwidth_mhz")
        features["occupancy_ratio"] = features.get("rf_occupancy_ratio")
