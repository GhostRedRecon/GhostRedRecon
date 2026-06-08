# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/recon/core/recon_engine.py
# VERSION:      v52.0.0 (FINAL LOCKED - SPECTRAL + BURST HYBRID SIGINT CORE)
# UPDATED:      2026-03-22
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
#                    ┌────────────────────┐
#                    │     HackRF SDR     │
#                    └────────┬───────────┘
#                             │
#                       IQ / RF Samples
#                             │
#                    ┌────────▼────────┐
#                    │    LiveFFT      │
#                    └────────┬────────┘
#                             │
#                     FFT Frames (Power Spectrum)
#                             │
#                  ┌──────────▼──────────┐
#                  │    ReconEngine      │   ← THIS FILE
#                  └──────────┬──────────┘
#                             │
#        ┌────────────────────┴────────────────────┐
#        │                                         │
#   FFT Spectral Detection                  Burst Detection
#   (continuous wideband scan)             (transient/temporal truth)
#        │                                         │
#        └────────────────────┬────────────────────┘
#                             │
#                    Normalized Detection Events
#                             │
#                       SignalEngine
#                             │
#               Protocol / Device / API Layers
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# ReconEngine is the LOW-LEVEL RF DETECTION CORE.
#
# It converts:
#   - FFT power spectrum frames
#   - IQ burst extraction results
#
# INTO:
#   - normalized RF detection events
#
# IMPORTANT:
#   ✔ This layer performs detection ONLY
#   ✔ It does NOT perform protocol classification
#   ✔ It does NOT perform device identification
#   ✔ It must preserve the SignalEngine dispatch contract
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Detect RF energy using adaptive thresholding
# ✔ Estimate noise floor robustly across changing environments
# ✔ Maintain band-aware and local spectrum sensitivity
# ✔ Cluster spectral peaks into candidate RF signals
# ✔ Estimate signal confidence from:
#     - power margin
#     - cluster width
#     - peak density
#     - temporal consistency
#     - spectral shape
# ✔ Extract bursts from IQ data when burst engine is available
# ✔ Normalize detections into a stable event schema
# ✔ Dispatch events to SignalEngine without changing interface
# ✔ Maintain real-time counters and observability
#
# SAFETY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Never block runtime pipeline
# ✔ Never crash on malformed FFT/IQ input
# ✔ Fail safely when burst extraction is unavailable
# ✔ Remain permissive enough to avoid zero-signal regressions
#
# FUTURE-READINESS RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Emit classifier-ready metadata without coupling to classifier logic
# ✔ Preserve additive evolution of event fields
# ✔ Support future spectral and temporal engines without changing dispatch
#
# =============================================================================
# ❌ NON-RESPONSIBILITIES
# =============================================================================
#
# ✘ Protocol classification
# ✘ Device identification
# ✘ Vendor inference
# ✘ Behavioral analysis
# ✘ SDR tuning / orchestration
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. LOCKED CONTRACT
# -----------------------------------------------------------------------------
# SignalEngine.update_signal(...) interface MUST NOT change.
#
# 2. DETECTION PURITY
# -----------------------------------------------------------------------------
# This file only detects and normalizes RF activity.
#
# 3. ADAPTIVE NOT FRAGILE
# -----------------------------------------------------------------------------
# Thresholding must adapt to changing spectrum conditions without becoming so
# strict that all detections disappear.
#
# 4. PERMISSIVE DETECTION, INTELLIGENT DOWNSTREAM FILTERING
# -----------------------------------------------------------------------------
# ReconEngine favors recall. SignalEngine and later layers can apply stronger
# intelligence-level filtering.
#
# 5. BURST-FIRST TRUTH, FFT-FIRST COVERAGE
# -----------------------------------------------------------------------------
# Burst detections are higher-trust when available. FFT detections maintain
# wideband continuity and fallback coverage.
#
# 6. ZERO BREAKAGE
# -----------------------------------------------------------------------------
# Existing startup, dispatch, and stats behavior must continue to work.
#
# =============================================================================
# 📦 SIGNAL OUTPUT SCHEMA (LOCKED + ADDITIVE)
# =============================================================================
#
# event = {
#     "timestamp": float,
#     "frequency_mhz": float,
#     "power_db": float,
#     "confidence": float,
#     "rf_band": str,
#     "engine": "fft" | "burst",
#     ... optional metadata
# }
#
# Optional FFT metadata may include:
#   "cluster_size"
#   "power_margin"
#   "temporal_consistency"
#   "noise_floor_db"
#   "adaptive_threshold_db"
#   "peak_density"
#   "bandwidth_estimate_mhz"
#   "bandwidth_class"
#   "spectral_flatness"
#   "edge_steepness"
#   "shape_score"
#   "signal_type"
#   "burst_ratio"
#   "periodicity"
#   "freq_variance"
#   "recon_version"
#   "detection_type"
#
# =============================================================================
# 🔍 DETECTION LOGIC AND BEHAVIOR
# =============================================================================
#
# FFT DETECTION PIPELINE
# -----------------------------------------------------------------------------
# 1. Sanitize FFT frame
# 2. Estimate global floor using:
#    - frame mean
#    - low percentile floor
#    - MAD-derived spread
#    - EMA running baseline
# 3. Estimate local floor using rolling local percentile
# 4. Compute adaptive threshold:
#    threshold = max(global_floor, local_floor) + margin_from_spread
# 5. Detect bins above threshold
# 6. Cluster adjacent bins into candidate signals
# 7. Estimate:
#    - center frequency
#    - bandwidth
#    - power margin
#    - peak density
#    - spectral shape
#    - temporal consistency
# 8. Classify coarse signal behavior:
#    - narrow / medium / wideband
#    - bursty / periodic / continuous
# 9. Dispatch normalized event
#
# BURST DETECTION PIPELINE
# -----------------------------------------------------------------------------
# 1. Pull IQ samples from SDR when available
# 2. Run burst extractor
# 3. Convert burst attributes into normalized event
# 4. Dispatch burst event to SignalEngine
#
# =============================================================================
# 🔄 CHANGES IN v52.0.0
# =============================================================================
#
# ✔ Preserved start(*args), stop(), _dispatch(), and get_stats()
# ✔ Preserved SignalEngine.update_signal(...) contract
# ✔ Added local-spectrum adaptive floor estimation
# ✔ Added spectral shape analysis (flatness, edge steepness, shape score)
# ✔ Added better bandwidth estimation and bandwidth class
# ✔ Added coarse signal behavior hints for downstream classifier
# ✔ Added burst-first confidence policy while preserving FFT fallback
# ✔ Preserved separation from intelligence layer
#
# =============================================================================

from __future__ import annotations

import threading
import time
from typing import Dict, Optional

import numpy as np

try:
    from backend.analysis.burst_extraction_engine import BurstExtractionEngine
except Exception:
    BurstExtractionEngine = None


class ReconEngine:

    VERSION = "52.0.0"

    # -------------------------------------------------------------------------
    # Adaptive detection tuning
    # -------------------------------------------------------------------------
    BASELINE_ALPHA = 0.12
    MAD_MULTIPLIER = 2.0
    MIN_POWER_MARGIN_DB = 1.2
    MIN_CLUSTER_SIZE = 1
    MIN_CONFIDENCE = 0.04
    CLUSTER_GAP_BINS = 3

    # -------------------------------------------------------------------------
    # Temporal reinforcement
    # -------------------------------------------------------------------------
    TEMPORAL_BIN_RESOLUTION_MHZ = 0.5
    TEMPORAL_DECAY = 0.88
    TEMPORAL_BOOST_MAX = 0.20

    # -------------------------------------------------------------------------
    # Local spectrum modeling
    # -------------------------------------------------------------------------
    LOCAL_WINDOW_BINS = 21
    LORA_CENTER_HINTS = (
        433.175, 433.375, 433.775, 433.92,
        867.1, 867.3, 867.5, 867.7, 867.9,
        868.1, 868.3, 868.5, 869.525,
        903.9, 904.1, 904.3, 904.5, 904.7, 904.9, 905.1, 905.3,
        923.3,
    )

    # -------------------------------------------------------------------------
    # Runtime pacing
    # -------------------------------------------------------------------------
    LOOP_SLEEP_SEC = 0.01

    def __init__(self, signal_engine=None):

        self._running = False
        self._thread: Optional[threading.Thread] = None

        self._fft = None
        self._sdr = None
        self.signal_engine = signal_engine

        self._burst_engine = None

        self._noise_floor = None
        self._band_noise_floors: Dict[str, float] = {}
        self._temporal_hits: Dict[str, float] = {}

        self._frames_processed = 0
        self._signals_detected = 0
        self._bursts_detected = 0

    # =========================================================================
    # START / STOP
    # =========================================================================
    def start(self, *args):

        if self._running:
            return

        if len(args) == 1:
            self._fft = args[0]
        elif len(args) == 2:
            self._sdr = args[0]
            self._fft = args[1]
        else:
            raise ValueError("Invalid start arguments")

        if self._sdr and hasattr(self._sdr, "get_iq_samples") and BurstExtractionEngine:
            self._burst_engine = BurstExtractionEngine()

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._thread = None

    # =========================================================================
    # MAIN LOOP
    # =========================================================================
    def _run(self):

        while self._running:
            try:
                # Burst path first: when available, it provides higher-trust
                # transient detection truth.
                if self._burst_engine:
                    self._process_bursts()

                frame = self._safe_get_frame()
                if frame is not None:
                    self._process_fft(frame)

            except Exception as e:
                print(f"🔥 [RECON ERROR] {e}")

            time.sleep(self.LOOP_SLEEP_SEC)

    # =========================================================================
    # FFT DETECTION
    # =========================================================================
    def _process_fft(self, frame):

        frame = np.asarray(frame, dtype=np.float32)
        if frame.size == 0:
            return

        frame = np.nan_to_num(frame, nan=-120.0, posinf=-120.0, neginf=-120.0)
        self._frames_processed += 1

        # ---------------------------------------------------------------------
        # Global floor estimation
        # ---------------------------------------------------------------------
        frame_mean = float(frame.mean())
        frame_p20 = float(np.percentile(frame, 20))
        frame_median = float(np.median(frame))
        mad = float(np.median(np.abs(frame - frame_median))) + 1e-6
        robust_std = 1.4826 * mad

        if self._noise_floor is None:
            self._noise_floor = frame_mean
        else:
            self._noise_floor = (
                (1.0 - self.BASELINE_ALPHA) * self._noise_floor
                + (self.BASELINE_ALPHA * frame_mean)
            )

        global_floor = max(float(self._noise_floor), frame_p20)

        # ---------------------------------------------------------------------
        # Local floor estimation
        # ---------------------------------------------------------------------
        local_floor = self._estimate_local_floor(frame)

        adaptive_threshold = np.maximum(global_floor, local_floor) + max(
            0.8, self.MAD_MULTIPLIER * robust_std
        )

        peaks = np.where(frame > adaptive_threshold)[0]
        clusters = self._cluster(peaks)

        fft_size = len(frame)

        for cluster in clusters:

            if len(cluster) < self.MIN_CLUSTER_SIZE:
                continue

            cluster = np.asarray(cluster, dtype=np.int32)
            cluster_values = frame[cluster]

            power = float(cluster_values.max())
            center_bin = int(np.mean(cluster))
            freq_mhz = self._bin_to_freq(center_bin, fft_size)
            rf_band = self._infer_band(freq_mhz)

            # band-aware baseline tracking
            band_floor = self._update_band_floor(rf_band, global_floor)
            local_cluster_floor = float(np.min(adaptive_threshold[cluster]))
            baseline_floor = max(global_floor, band_floor, local_cluster_floor)

            margin = power - baseline_floor
            if margin < self.MIN_POWER_MARGIN_DB:
                continue

            cluster_size = int(len(cluster))
            cluster_span_bins = int(cluster[-1] - cluster[0] + 1)
            peak_density = float(cluster_size / max(1, cluster_span_bins))
            bandwidth_estimate_mhz = self._estimate_bandwidth_mhz(cluster_span_bins, fft_size)

            shape = self._analyze_spectral_shape(cluster_values)
            temporal_consistency = self._update_temporal_consistency(freq_mhz)
            signal_type = self._infer_signal_type(
                bandwidth_estimate_mhz=bandwidth_estimate_mhz,
                temporal_consistency=temporal_consistency,
                peak_density=peak_density,
                shape_score=shape["shape_score"],
            )
            phy_hints = self._infer_phy_hints(
                freq_mhz=freq_mhz,
                rf_band=rf_band,
                bandwidth_estimate_mhz=bandwidth_estimate_mhz,
                peak_density=peak_density,
                signal_type=signal_type,
                temporal_consistency=temporal_consistency,
                shape=shape,
            )

            confidence = self._compute_fft_confidence(
                cluster_size=cluster_size,
                power_margin_db=margin,
                temporal_consistency=temporal_consistency,
                peak_density=peak_density,
                shape_score=shape["shape_score"],
            )

            if confidence < self.MIN_CONFIDENCE:
                continue

            event = {
                "timestamp": time.time(),
                "frequency_mhz": freq_mhz,
                "power_db": power,
                "confidence": confidence,
                "rf_band": rf_band,
                "engine": "fft",
                "cluster_size": cluster_size,
                "power_margin": round(margin, 3),
                "temporal_consistency": temporal_consistency,
                "noise_floor_db": round(baseline_floor, 3),
                "adaptive_threshold_db": round(float(np.mean(adaptive_threshold[cluster])), 3),
                "peak_density": round(peak_density, 4),
                "bandwidth_estimate_mhz": round(bandwidth_estimate_mhz, 4),
                "bandwidth_class": self._bandwidth_class(bandwidth_estimate_mhz),
                "spectral_flatness": shape["spectral_flatness"],
                "edge_steepness": shape["edge_steepness"],
                "shape_score": shape["shape_score"],
                "spectral_chirp_hint": shape["spectral_chirp_hint"],
                "signal_type": signal_type,
                "burst_ratio": 1.0 if signal_type == "burst" else 0.0,
                "periodicity": temporal_consistency if signal_type == "periodic" else 0.0,
                "freq_variance": 0.0,
                "recon_version": self.VERSION,
                "detection_type": "fft_cluster",
            }
            event.update(phy_hints)

            self._signals_detected += 1
            self._dispatch(event)

    # =========================================================================
    # BURST DETECTION
    # =========================================================================
    def _process_bursts(self):

        iq = self._safe_get_iq()
        if iq is None:
            return

        freq = self._get_center_freq()
        bursts = self._burst_engine.process_iq(iq, freq)

        for burst in bursts or []:
            try:
                center_freq = float(burst["center_freq_mhz"])
                max_power = float(burst["max_power"])
                snr_est = float(burst.get("snr_estimate", 1.0))
                duration_ms = float(burst.get("duration_ms", 0.0) or 0.0)

                confidence = min(1.0, max(0.08, (snr_est / 18.0)))

                event = {
                    "timestamp": float(burst["timestamp"]),
                    "frequency_mhz": center_freq,
                    "power_db": max_power,
                    "confidence": round(confidence, 3),
                    "rf_band": self._infer_band(center_freq),
                    "engine": "burst",
                    "snr_estimate": snr_est,
                    "duration_ms": duration_ms,
                    "signal_type": "burst",
                    "burst_ratio": 1.0,
                    "periodicity": 0.0,
                    "recon_version": self.VERSION,
                    "detection_type": "iq_burst",
                }

                self._bursts_detected += 1
                self._dispatch(event)

            except Exception:
                continue

    # =========================================================================
    # CLUSTERING
    # =========================================================================
    def _cluster(self, peaks):

        if len(peaks) == 0:
            return []

        clusters = []
        current = [int(peaks[0])]

        for i in range(1, len(peaks)):
            if int(peaks[i]) - int(peaks[i - 1]) <= self.CLUSTER_GAP_BINS:
                current.append(int(peaks[i]))
            else:
                clusters.append(current)
                current = [int(peaks[i])]

        clusters.append(current)
        return clusters

    # =========================================================================
    # CONFIDENCE MODEL
    # =========================================================================
    def _compute_fft_confidence(
        self,
        cluster_size: int,
        power_margin_db: float,
        temporal_consistency: float,
        peak_density: float,
        shape_score: float,
    ) -> float:
        size_term = min(0.28, cluster_size / 12.0)
        margin_term = min(0.28, power_margin_db / 9.0)
        temporal_term = min(self.TEMPORAL_BOOST_MAX, temporal_consistency * self.TEMPORAL_BOOST_MAX)
        density_term = min(0.10, peak_density * 0.10)
        shape_term = min(0.14, shape_score * 0.14)

        score = size_term + margin_term + temporal_term + density_term + shape_term
        return round(min(1.0, max(0.0, score)), 4)

    def _update_temporal_consistency(self, freq_mhz: float) -> float:
        key = f"{round(freq_mhz / self.TEMPORAL_BIN_RESOLUTION_MHZ) * self.TEMPORAL_BIN_RESOLUTION_MHZ:.1f}"

        for k in list(self._temporal_hits.keys()):
            self._temporal_hits[k] *= self.TEMPORAL_DECAY
            if self._temporal_hits[k] < 0.05:
                del self._temporal_hits[k]

        current = self._temporal_hits.get(key, 0.0)
        current = min(1.0, current + 0.22)
        self._temporal_hits[key] = current
        return round(current, 4)

    # =========================================================================
    # SPECTRAL / LOCAL ANALYSIS
    # =========================================================================
    def _estimate_local_floor(self, frame: np.ndarray) -> np.ndarray:
        """
        Rolling local percentile floor.
        Keeps threshold adaptive to local spectral neighborhoods without using
        heavy external dependencies.
        """
        n = len(frame)
        window = self.LOCAL_WINDOW_BINS
        half = window // 2
        local = np.empty(n, dtype=np.float32)

        for i in range(n):
            start = max(0, i - half)
            end = min(n, i + half + 1)
            local[i] = np.percentile(frame[start:end], 25)

        return local

    def _analyze_spectral_shape(self, cluster_values: np.ndarray) -> Dict[str, float]:
        """
        Lightweight spectral shape model for classifier-ready metadata.
        """
        vals = np.asarray(cluster_values, dtype=np.float32)
        vals = np.maximum(vals - np.min(vals) + 1e-3, 1e-3)

        arithmetic = float(np.mean(vals))
        geometric = float(np.exp(np.mean(np.log(vals))))
        flatness = geometric / max(arithmetic, 1e-6)

        if len(vals) >= 2:
            left = float(vals[0])
            right = float(vals[-1])
            peak = float(np.max(vals))
            edge_steepness = (peak - ((left + right) / 2.0)) / max(peak, 1e-6)
            chirp_hint = float(np.std(np.diff(vals)))
        else:
            edge_steepness = 0.0
            chirp_hint = 0.0

        shape_score = max(0.0, min(1.0, (1.0 - flatness) * 0.6 + edge_steepness * 0.4))

        return {
            "spectral_flatness": round(float(flatness), 4),
            "edge_steepness": round(float(max(0.0, edge_steepness)), 4),
            "shape_score": round(float(shape_score), 4),
            "spectral_chirp_hint": round(float(chirp_hint), 4),
        }

    def _infer_phy_hints(
        self,
        *,
        freq_mhz: float,
        rf_band: str,
        bandwidth_estimate_mhz: float,
        peak_density: float,
        signal_type: str,
        temporal_consistency: float,
        shape: Dict[str, float],
    ) -> Dict[str, object]:
        flatness = float(shape.get("spectral_flatness", 0.0) or 0.0)
        chirp_hint = float(shape.get("spectral_chirp_hint", 0.0) or 0.0)
        edge = float(shape.get("edge_steepness", 0.0) or 0.0)

        hints: Dict[str, object] = {
            "rf_modulation_hint": None,
            "rf_chirp_detected": False,
            "rf_frame_structure": None,
            "rf_frame_protocol_hint": None,
            "rf_frame_confidence": 0.0,
        }

        if rf_band != "subGHz":
            return hints

        narrow_subghz = 0.003 <= bandwidth_estimate_mhz <= 0.60
        periodic_like = signal_type in {"periodic", "burst"} or temporal_consistency >= 0.70
        lora_center_like = min(abs(freq_mhz - center) for center in self.LORA_CENTER_HINTS) <= 0.9
        wmbus_center_like = min(abs(freq_mhz - center) for center in (868.30, 868.95, 869.525)) <= 0.18
        strong_chirp_like = (
            narrow_subghz
            and periodic_like
            and lora_center_like
            and chirp_hint >= 2.0
            and peak_density <= 3.0
        )

        chirp_like = (
            narrow_subghz
            and periodic_like
            and lora_center_like
            and flatness >= 0.20
            and chirp_hint >= 0.12
            and peak_density <= 8.0
        )

        if strong_chirp_like or chirp_like:
            hints["rf_modulation_hint"] = "LoRa_like"
            hints["rf_chirp_detected"] = True
            hints["rf_frame_structure"] = "chirp"
            hints["rf_frame_protocol_hint"] = "LoRa"
            hints["rf_frame_confidence"] = round(min(0.9, 0.45 + min(chirp_hint, 2.0) * 0.18 + (temporal_consistency * 0.15)), 4)
            hints["rf_subghz_profile"] = "lpwan_lora_like"
            return hints

        if narrow_subghz and peak_density <= 18.0:
            hints["rf_modulation_hint"] = "FSK_like"
            if (
                periodic_like
                and wmbus_center_like
                and 0.004 <= bandwidth_estimate_mhz <= 0.25
            ):
                hints["rf_frame_structure"] = "metering_burst"
                hints["rf_frame_protocol_hint"] = "WirelessMbus"
                hints["rf_frame_confidence"] = round(min(0.86, 0.38 + (temporal_consistency * 0.24)), 4)
                hints["rf_subghz_profile"] = "wireless_mbus_like"
                return hints
            if periodic_like and edge >= 0.20:
                hints["rf_frame_structure"] = "telemetry_burst"
                hints["rf_frame_protocol_hint"] = "SubGHz"
                hints["rf_frame_confidence"] = round(min(0.8, 0.35 + (temporal_consistency * 0.25)), 4)
            return hints

        if bandwidth_estimate_mhz < 0.25 and peak_density > 18.0:
            hints["rf_modulation_hint"] = "Continuous_Carrier"

        return hints

    def _infer_signal_type(
        self,
        bandwidth_estimate_mhz: float,
        temporal_consistency: float,
        peak_density: float,
        shape_score: float,
    ) -> str:
        """
        Coarse detection behavior classification for downstream classifier use.
        """
        if temporal_consistency > 0.65 and bandwidth_estimate_mhz < 0.35:
            return "periodic"
        if bandwidth_estimate_mhz < 0.25 and peak_density > 0.8 and shape_score > 0.45:
            return "narrow"
        if bandwidth_estimate_mhz > 2.0:
            return "wideband"
        return "continuous"

    def _bandwidth_class(self, bandwidth_estimate_mhz: float) -> str:
        if bandwidth_estimate_mhz < 0.25:
            return "narrow"
        if bandwidth_estimate_mhz < 2.0:
            return "medium"
        return "wide"

    def _update_band_floor(self, rf_band: str, observed_floor: float) -> float:
        current = self._band_noise_floors.get(rf_band)
        if current is None:
            self._band_noise_floors[rf_band] = observed_floor
        else:
            self._band_noise_floors[rf_band] = (
                (1.0 - self.BASELINE_ALPHA) * current
                + (self.BASELINE_ALPHA * observed_floor)
            )
        return float(self._band_noise_floors[rf_band])

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _estimate_bandwidth_mhz(self, cluster_span_bins: int, fft_size: int) -> float:
        sample_rate = getattr(self._sdr, "sample_rate", 2_000_000)
        bin_width_hz = sample_rate / max(1, fft_size)
        return (cluster_span_bins * bin_width_hz) / 1e6

    def _bin_to_freq(self, bin_index, fft_size):

        center = self._get_center_freq()
        sample_rate = getattr(self._sdr, "sample_rate", 2_000_000)

        bin_width = sample_rate / fft_size
        offset = (bin_index - fft_size // 2) * bin_width

        return center + (offset / 1e6)

    def _infer_band(self, freq):

        if 2400 <= freq <= 2500:
            return "2.4GHz"
        if freq < 1000:
            return "subGHz"
        return "other"

    def _safe_get_frame(self):
        try:
            return self._fft.get_latest_frame()
        except Exception:
            return None

    def _safe_get_iq(self):
        try:
            return self._sdr.get_iq_samples()
        except Exception:
            return None

    def _get_center_freq(self):
        try:
            return self._sdr.get_state().get("freq_mhz", 0.0)
        except Exception:
            return 0.0

    # =========================================================================
    # DISPATCH (LOCKED CONTRACT)
    # =========================================================================
    def _dispatch(self, event):

        if not self.signal_engine:
            return

        sid = f"{round(event['frequency_mhz'], 3)}"

        try:
            self.signal_engine.update_signal(
                sid=sid,
                freq_mhz=event["frequency_mhz"],
                power_db=event["power_db"],
                metadata=event,
            )
        except Exception as e:
            print(f"⚠️ Dispatch error: {e}")

    # =========================================================================
    # STATS
    # =========================================================================
    def get_stats(self):

        return {
            "running": self._running,
            "frames_processed": self._frames_processed,
            "signals_detected": self._signals_detected,
            "bursts_detected": self._bursts_detected,
            "version": self.VERSION,
        }
