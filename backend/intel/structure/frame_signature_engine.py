# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/frame_signature_engine.py
# VERSION:      v1.0.0 (STRUCTURE-LEVEL RF INTELLIGENCE ENGINE)
# LAST UPDATED: 2026-03-03
#
# =============================================================================
# PURPOSE
# -----------------------------------------------------------------------------
# Extracts structure-level intelligence from RF bursts WITHOUT full decoding.
#
# This module infers:
#   - Frame role (infrastructure, beacon, remote, etc.)
#   - Periodicity characteristics
#   - Payload entropy profile
#   - Rolling counter detection
#   - Replay window estimation
#   - Advertising interval clustering
#   - Infrastructure probability heuristics
#
# DESIGN PRINCIPLES
# -----------------------------------------------------------------------------
# ✔ No packet decoding required
# ✔ Statistical & temporal inference only
# ✔ Protocol-aware but modulation-driven
# ✔ Deterministic
# ✔ Thread-safe (no internal state mutation)
# ✔ Compatible with existing SignalEngine pipeline
# =============================================================================

from typing import Dict, Any, List
import math
import numpy as np


class FrameSignatureEngine:

    # =========================================================================
    # ENTRY POINT
    # =========================================================================

    def process(self, record: Dict[str, Any]) -> Dict[str, Any]:

        modulation = record.get("modulation_guess", "")
        rf = record.get("rf_features", {}) or {}

        result = {}

        # Universal metrics
        result.update(self._compute_temporal_metrics(record))
        result.update(self._compute_entropy_metrics(record))

        # Protocol-specific structure inference
        if modulation == "Wideband_OFDM_like":
            result.update(self._wifi_structure(record))

        elif modulation == "DSSS_OQPSK_like":
            result.update(self._zigbee_structure(record))

        elif modulation == "OOK":
            result.update(self._subghz_structure(record))

        elif modulation == "LoRa_like":
            result.update(self._lora_structure(record))

        return result

    # =========================================================================
    # UNIVERSAL TEMPORAL METRICS
    # =========================================================================

    def _compute_temporal_metrics(self, record: Dict[str, Any]) -> Dict[str, Any]:

        interval = float(record.get("avg_interarrival_sec", 0)) * 1000
        variance = float(record.get("interval_variance", 0))
        burst_duration = float(record.get("burst_duration_ms", 0))

        periodicity_score = 0.0
        if interval > 0:
            periodicity_score = max(
                0.0,
                min(1.0, 1.0 - (variance / max(interval, 1)))
            )

        return {
            "frame_interval_ms": round(interval, 2),
            "frame_periodicity_score": round(periodicity_score, 3),
            "frame_burst_duration_ms": burst_duration,
        }

    # =========================================================================
    # PAYLOAD ENTROPY METRICS
    # =========================================================================

    def _compute_entropy_metrics(self, record: Dict[str, Any]) -> Dict[str, Any]:

        iq = record.get("rf_features", {}).get("iq_samples")

        if iq is None or len(iq) < 128:
            return {
                "payload_entropy_score": 0.0,
                "counter_progression_detected": False
            }

        iq = np.array(iq, dtype=np.complex64)

        amplitude = np.abs(iq)
        amplitude_norm = amplitude / (np.max(amplitude) + 1e-9)

        hist, _ = np.histogram(amplitude_norm, bins=16, range=(0, 1), density=True)
        hist = hist + 1e-9

        entropy = -np.sum(hist * np.log2(hist)) / math.log2(len(hist))
        entropy = float(min(max(entropy, 0.0), 1.0))

        # Counter progression heuristic
        # Detect monotonic change in mean amplitude across segments
        segments = np.array_split(amplitude_norm, 4)
        means = [np.mean(s) for s in segments]
        diffs = np.diff(means)

        monotonic = all(d > 0 for d in diffs) or all(d < 0 for d in diffs)

        return {
            "payload_entropy_score": round(entropy, 3),
            "counter_progression_detected": monotonic
        }

    # =========================================================================
    # WIFI STRUCTURE INFERENCE
    # =========================================================================

    def _wifi_structure(self, record: Dict[str, Any]) -> Dict[str, Any]:

        periodicity = record.get("frame_periodicity_score", 0)
        interval = record.get("frame_interval_ms", 0)
        persistence = record.get("persistence_confidence", 0)
        width = record.get("rf_width_mhz", 0)

        role = "WIFI_UNKNOWN"

        # Beacon detection (≈100ms interval)
        if 80 <= interval <= 120 and periodicity > 0.6:
            role = "WIFI_BEACON"

        # Infrastructure detection
        elif persistence > 0.6 and width >= 18:
            role = "WIFI_INFRASTRUCTURE"

        # Data-heavy device
        elif interval < 20 and persistence > 0.3:
            role = "WIFI_DATA_DEVICE"

        infra_probability = min(
            1.0,
            (persistence * 0.5) + (0.5 if width >= 18 else 0)
        )

        return {
            "frame_role": role,
            "infrastructure_probability": round(infra_probability, 3),
            "beacon_interval_ms": interval if role == "WIFI_BEACON" else None
        }

    # =========================================================================
    # ZIGBEE STRUCTURE INFERENCE
    # =========================================================================

    def _zigbee_structure(self, record: Dict[str, Any]) -> Dict[str, Any]:

        persistence = record.get("persistence_confidence", 0)
        periodicity = record.get("frame_periodicity_score", 0)
        entropy = record.get("payload_entropy_score", 0)

        role = "ZIGBEE_UNKNOWN"

        if persistence > 0.6 and entropy < 0.6:
            role = "ZIGBEE_COORDINATOR"

        elif periodicity > 0.5:
            role = "ZIGBEE_END_DEVICE"

        elif persistence > 0.3:
            role = "ZIGBEE_ROUTER"

        return {
            "frame_role": role,
            "mesh_participation_score": round(persistence, 3)
        }

    # =========================================================================
    # SUBGHZ STRUCTURE INFERENCE
    # =========================================================================

    def _subghz_structure(self, record: Dict[str, Any]) -> Dict[str, Any]:

        entropy = record.get("payload_entropy_score", 0)
        periodicity = record.get("frame_periodicity_score", 0)
        interval = record.get("frame_interval_ms", 0)

        remote_type = "UNKNOWN"

        if entropy < 0.4:
            remote_type = "FIXED_CODE"

        elif entropy > 0.7:
            remote_type = "ROLLING_CODE"

        replay_window = None
        if remote_type == "ROLLING_CODE":
            replay_window = min(interval * 0.5, 2000)

        return {
            "frame_role": "SUBGHZ_REMOTE",
            "remote_code_type": remote_type,
            "replay_window_estimate_ms": replay_window
        }

    # =========================================================================
    # LORA STRUCTURE INFERENCE
    # =========================================================================

    def _lora_structure(self, record: Dict[str, Any]) -> Dict[str, Any]:

        bw = record.get("rf_width_mhz", 0)
        duration = record.get("frame_burst_duration_ms", 0)

        sf_estimate = None
        if duration > 100:
            sf_estimate = 12
        elif duration > 50:
            sf_estimate = 9
        else:
            sf_estimate = 7

        return {
            "frame_role": "LORA_DEVICE",
            "lora_spreading_factor_estimate": sf_estimate,
            "lora_bandwidth_mhz": bw
        }
