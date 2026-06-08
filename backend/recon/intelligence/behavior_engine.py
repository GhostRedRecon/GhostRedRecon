# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF TEMPORAL BEHAVIOR INTELLIGENCE ENGINE
# FILE:         backend/recon/intelligence/behavior_engine.py
#
# VERSION:      v4.0.0 (PHASE-3 PRODUCTION TEMPORAL INTELLIGENCE UPGRADE)
# UPDATED:      2026-03-16
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is an RF reconnaissance and device intelligence platform built for
# red-team operations. The platform must convert passive RF observations into
# operational intelligence about devices, behaviors, ecosystems, and likely
# attack surfaces.
#
# This module provides the temporal behavior layer for that mission.
#
# Many RF devices reveal important operational traits not from payload decoding,
# but from when and how they transmit:
#
# • fixed-interval beaconing
# • bursty user-triggered activity
# • continuous session traffic
# • low-rate telemetry
# • opportunistic irregular chatter
# • short command/response behavior
#
# The purpose of this engine is to convert timestamped emitter observations into
# stable, explainable temporal behavior features that can be consumed by:
#
# • device_fusion.py
# • device_intelligence.py
# • network_correlation.py
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# ReconEngine / SignalEngine
#     ↓
# Emitter / signal observations
#     ↓
# RFBehaviorEngine   ← THIS MODULE
#     ↓
# Temporal feature extraction
#     ↓
# Behavior pattern inference
#     ↓
# Behavior confidence + explainability
#     ↓
# Device intelligence / network correlation / analyst output
#
#
# INPUT MODEL
# -----------------------------------------------------------------------------
# The engine accepts:
#
# 1. update(signal_id, timestamp)
#    - backwards-compatible minimal interface
#
# 2. update(signal_id, timestamp, observation_dict)
#    - richer interface that supports:
#         freq_mhz / frequency_mhz / rf_frequency_mhz
#         protocol / rf_protocol
#         channel / rf_channel
#         power_db / power_dbm / rf_power_db
#         burst_duration_ms / rf_burst_duration_ms
#         dwell_sec / dwell_time_sec
#
#
# OUTPUT MODEL
# -----------------------------------------------------------------------------
# • rf_interval_avg
# • rf_interval_std
# • rf_interval_variance
# • rf_interval_median
# • rf_interval_min
# • rf_interval_max
# • rf_interval_cv
# • rf_observation_count
# • rf_burst_clusters
# • rf_burst_ratio
# • rf_stability_score
# • rf_behavior_pattern
# • rf_behavior_subtype
# • rf_behavior_confidence
# • rf_behavior_reasoning
# • rf_behavior_device_hint
# • rf_behavior_tags
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. TEMPORAL RF INTELLIGENCE
# -----------------------------------------------------------------------------
# Timing behavior is often the strongest protocol-agnostic clue to device role.
#
#
# 2. REALTIME SAFE
# -----------------------------------------------------------------------------
# The engine must remain lightweight and suitable for continuous SDR operation.
#
#
# 3. PROTOCOL AGNOSTIC, CONTEXT AWARE
# -----------------------------------------------------------------------------
# The engine must work without decoding, but should consume upstream hints when
# available to improve behavioral interpretation.
#
#
# 4. EXPLAINABLE OUTPUT
# -----------------------------------------------------------------------------
# Every inferred behavior should include reasoning and supporting tags.
#
#
# 5. SAFE CONFIDENCE HANDLING
# -----------------------------------------------------------------------------
# Stable timing alone does not guarantee identity. The engine outputs behavior
# confidence, not product certainty.
#
#
# 6. BOUNDED MEMORY + STALE ENTRY CONTROL
# -----------------------------------------------------------------------------
# All per-signal state must remain bounded for long-running production use.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • timestamp tracking
# • interval analysis
# • burst cluster detection
# • periodicity estimation
# • temporal stability scoring
# • behavior pattern inference
# • conservative device-role hints
# • stale history cleanup
#
#
# This module is NOT responsible for:
#
# • SDR control
# • FFT generation
# • packet decoding
# • modulation classification
# • final product/vendor attribution
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v1.x
#     basic interval tracking
#
# v2.x
#     burst detection + periodicity
#
# v3.x
#     coefficient-of-variation stability scoring
#
# v4.x
#     production temporal intelligence with:
#       - mixed-schema support
#       - richer behavior taxonomy
#       - explicit cleanup
#       - safer confidence model
#       - explainable analyst-facing output
#
# =============================================================================

from __future__ import annotations

import math
import statistics
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional


class RFBehaviorEngine:
    """
    Production-grade temporal behavior analysis for RF emitters.

    Primary usage:
        engine = RFBehaviorEngine()
        result = engine.update(signal_id, timestamp, observation)

    Backwards-compatible usage:
        result = engine.update(signal_id, timestamp)
    """

    VERSION = "4.0.0"

    # -------------------------------------------------------------------------
    # MEMORY / LIFECYCLE
    # -------------------------------------------------------------------------

    MAX_HISTORY = 160
    SIGNAL_TIMEOUT_SEC = 900.0
    CLEANUP_INTERVAL_SEC = 60.0

    # -------------------------------------------------------------------------
    # ANALYSIS THRESHOLDS
    # -------------------------------------------------------------------------

    MIN_OBSERVATIONS = 6
    MIN_INTERVALS = 5

    BURST_THRESHOLD_SEC = 0.025
    FAST_CONTINUOUS_INTERVAL_SEC = 0.050
    PERIODIC_CV_THRESHOLD = 0.12
    STABLE_CV_THRESHOLD = 0.20
    IRREGULAR_CV_THRESHOLD = 0.60

    SHORT_TELEMETRY_MIN_SEC = 0.50
    SHORT_TELEMETRY_MAX_SEC = 3.00

    LONG_TELEMETRY_MIN_SEC = 3.00
    LONG_TELEMETRY_MAX_SEC = 120.00

    # -------------------------------------------------------------------------
    # INIT
    # -------------------------------------------------------------------------

    def __init__(self) -> None:
        self.signal_history: Dict[str, Dict[str, Any]] = {}
        self._last_cleanup_ts = 0.0

    # -------------------------------------------------------------------------
    # PUBLIC API
    # -------------------------------------------------------------------------

    def update(
        self,
        signal_id: str,
        timestamp: float,
        observation: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Update temporal state for a signal/emitter and return a behavior result
        once enough observations have been collected.

        Parameters
        ----------
        signal_id:
            Stable emitter/signal identifier.

        timestamp:
            Observation time in seconds (monotonic or epoch-like, but consistent).

        observation:
            Optional mixed-schema observation metadata. Safe to omit.

        Returns
        -------
        Dict[str, Any] | None
            Behavior intelligence result, or None if insufficient history.
        """

        if not signal_id:
            return None

        ts = self._safe_float(timestamp, default=None)
        if ts is None:
            return None

        obs = observation or {}

        self._maybe_cleanup(ts)

        entry = self.signal_history.get(signal_id)
        if entry is None:
            entry = self._new_entry()
            self.signal_history[signal_id] = entry

        timestamps: Deque[float] = entry["timestamps"]
        meta_history: Deque[Dict[str, Any]] = entry["meta"]

        # Reject out-of-order timestamps that would corrupt interval math.
        if timestamps and ts <= timestamps[-1]:
            entry["out_of_order_events"] += 1
            entry["last_seen"] = max(entry["last_seen"], ts)
            return self._analyze(entry) if len(timestamps) >= self.MIN_OBSERVATIONS else None

        timestamps.append(ts)
        meta_history.append(self._normalize_observation(obs))
        entry["last_seen"] = ts
        entry["update_count"] += 1

        if len(timestamps) < self.MIN_OBSERVATIONS:
            return None

        return self._analyze(entry)

    def cleanup(self, now: Optional[float] = None) -> int:
        """
        Remove stale signal histories.

        Returns number of deleted entries.
        """
        now_ts = self._safe_float(now, default=time.time())
        deleted = 0

        for signal_id in list(self.signal_history.keys()):
            entry = self.signal_history[signal_id]
            if now_ts - entry["last_seen"] > self.SIGNAL_TIMEOUT_SEC:
                del self.signal_history[signal_id]
                deleted += 1

        self._last_cleanup_ts = now_ts
        return deleted

    def state(self) -> Dict[str, Any]:
        """
        Lightweight operational state for diagnostics.
        """
        return {
            "version": self.VERSION,
            "tracked_signals": len(self.signal_history),
            "max_history": self.MAX_HISTORY,
            "signal_timeout_sec": self.SIGNAL_TIMEOUT_SEC,
            "min_observations": self.MIN_OBSERVATIONS,
        }

    # -------------------------------------------------------------------------
    # INTERNAL STATE HELPERS
    # -------------------------------------------------------------------------

    def _new_entry(self) -> Dict[str, Any]:
        return {
            "timestamps": deque(maxlen=self.MAX_HISTORY),
            "meta": deque(maxlen=self.MAX_HISTORY),
            "last_seen": 0.0,
            "update_count": 0,
            "out_of_order_events": 0,
        }

    def _maybe_cleanup(self, now_ts: float) -> None:
        if (now_ts - self._last_cleanup_ts) >= self.CLEANUP_INTERVAL_SEC:
            self.cleanup(now_ts)

    def _normalize_observation(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        freq_mhz = self._safe_float(
            self._first_present(
                observation,
                "rf_frequency_mhz",
                "frequency_mhz",
                "freq_mhz",
                "center_freq_mhz",
            ),
            default=None,
        )

        protocol = self._first_present(
            observation,
            "rf_protocol",
            "protocol",
            "classified_protocol",
            "protocol_label",
        )

        channel = self._first_present(
            observation,
            "rf_channel",
            "channel",
            "wifi_channel",
        )

        power_db = self._safe_float(
            self._first_present(
                observation,
                "rf_power_db",
                "power_db",
                "power_dbm",
                "avg_power_db",
            ),
            default=None,
        )

        burst_duration_ms = self._safe_float(
            self._first_present(
                observation,
                "rf_burst_duration_ms",
                "burst_duration_ms",
                "burst_ms",
            ),
            default=None,
        )

        dwell_sec = self._safe_float(
            self._first_present(
                observation,
                "dwell_sec",
                "dwell_time_sec",
                "stage_dwell_sec",
            ),
            default=None,
        )

        return {
            "frequency_mhz": freq_mhz,
            "protocol": str(protocol).strip() if protocol is not None else None,
            "channel": channel,
            "power_db": power_db,
            "burst_duration_ms": burst_duration_ms,
            "dwell_sec": dwell_sec,
        }

    # -------------------------------------------------------------------------
    # ANALYSIS
    # -------------------------------------------------------------------------

    def _analyze(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        timestamps = list(entry["timestamps"])
        meta = list(entry["meta"])

        if len(timestamps) < self.MIN_OBSERVATIONS:
            return None

        intervals = self._intervals(timestamps)
        if len(intervals) < self.MIN_INTERVALS:
            return None

        mean_interval = statistics.mean(intervals)
        median_interval = statistics.median(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        variance = statistics.pvariance(intervals) if len(intervals) > 1 else 0.0
        min_interval = min(intervals)
        max_interval = max(intervals)

        cv = (std_interval / mean_interval) if mean_interval > 0 else 0.0

        burst_clusters = self._detect_burst_clusters(intervals)
        burst_ratio = self._burst_ratio(intervals)

        stability = self._stability_score(cv, len(intervals))
        periodicity_score = self._periodicity_score(cv, mean_interval, intervals)

        behavior_pattern = self._classify_pattern(
            mean_interval=mean_interval,
            cv=cv,
            burst_clusters=burst_clusters,
            burst_ratio=burst_ratio,
            periodicity_score=periodicity_score,
        )

        behavior_subtype = self._classify_subtype(
            mean_interval=mean_interval,
            cv=cv,
            burst_clusters=burst_clusters,
            burst_ratio=burst_ratio,
            behavior_pattern=behavior_pattern,
            meta=meta,
        )

        tags = self._build_behavior_tags(
            mean_interval=mean_interval,
            cv=cv,
            burst_clusters=burst_clusters,
            burst_ratio=burst_ratio,
            periodicity_score=periodicity_score,
            meta=meta,
            behavior_pattern=behavior_pattern,
            behavior_subtype=behavior_subtype,
        )

        reasoning = self._build_reasoning(
            mean_interval=mean_interval,
            cv=cv,
            burst_clusters=burst_clusters,
            burst_ratio=burst_ratio,
            periodicity_score=periodicity_score,
            behavior_pattern=behavior_pattern,
            behavior_subtype=behavior_subtype,
            meta=meta,
        )

        device_hint = self._infer_device_hint(
            mean_interval=mean_interval,
            cv=cv,
            burst_clusters=burst_clusters,
            burst_ratio=burst_ratio,
            behavior_pattern=behavior_pattern,
            behavior_subtype=behavior_subtype,
            meta=meta,
        )

        confidence = self._behavior_confidence(
            observation_count=len(timestamps),
            stability_score=stability,
            periodicity_score=periodicity_score,
            behavior_pattern=behavior_pattern,
            burst_ratio=burst_ratio,
            out_of_order_events=entry["out_of_order_events"],
        )

        result: Dict[str, Any] = {
            "rf_interval_avg": round(mean_interval, 4),
            "rf_interval_std": round(std_interval, 6),
            "rf_interval_variance": round(variance, 6),
            "rf_interval_median": round(float(median_interval), 4),
            "rf_interval_min": round(min_interval, 4),
            "rf_interval_max": round(max_interval, 4),
            "rf_interval_cv": round(cv, 4),
            "rf_observation_count": len(timestamps),
            "rf_burst_clusters": burst_clusters,
            "rf_burst_ratio": round(burst_ratio, 4),
            "rf_stability_score": round(stability, 4),
            "rf_periodicity_score": round(periodicity_score, 4),
            "rf_behavior_pattern": behavior_pattern,
            "rf_behavior_subtype": behavior_subtype,
            "rf_behavior_confidence": round(confidence, 4),
            "rf_behavior_reasoning": reasoning,
            "rf_behavior_tags": tags,
        }

        if device_hint:
            result["rf_behavior_device_hint"] = device_hint

        # Helpful passthrough context for downstream engines.
        protocol = self._dominant_meta_value(meta, "protocol")
        freq_mhz = self._dominant_numeric_band(meta, "frequency_mhz")
        channel = self._dominant_meta_value(meta, "channel")

        if protocol is not None:
            result["rf_behavior_protocol_hint"] = protocol
        if freq_mhz is not None:
            result["rf_behavior_frequency_mhz"] = round(freq_mhz, 3)
        if channel is not None:
            result["rf_behavior_channel_hint"] = channel

        return result

    # -------------------------------------------------------------------------
    # TEMPORAL FEATURES
    # -------------------------------------------------------------------------

    def _intervals(self, timestamps: List[float]) -> List[float]:
        intervals: List[float] = []
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            if delta > 0:
                intervals.append(delta)
        return intervals

    def _detect_burst_clusters(self, intervals: List[float]) -> int:
        cluster_len = 0
        clusters = 0

        for interval in intervals:
            if interval <= self.BURST_THRESHOLD_SEC:
                cluster_len += 1
            else:
                if cluster_len >= 2:
                    clusters += 1
                cluster_len = 0

        if cluster_len >= 2:
            clusters += 1

        return clusters

    def _burst_ratio(self, intervals: List[float]) -> float:
        if not intervals:
            return 0.0
        bursty = sum(1 for x in intervals if x <= self.BURST_THRESHOLD_SEC)
        return bursty / float(len(intervals))

    def _stability_score(self, cv: float, interval_count: int) -> float:
        """
        Stability is a measure of interval regularity, not identity certainty.
        """
        base: float
        if cv < 0.05:
            base = 0.96
        elif cv < 0.10:
            base = 0.90
        elif cv < 0.20:
            base = 0.80
        elif cv < 0.35:
            base = 0.65
        elif cv < 0.60:
            base = 0.45
        else:
            base = 0.22

        # Small sample penalty.
        if interval_count < 8:
            base *= 0.88
        elif interval_count < 12:
            base *= 0.94

        return max(0.0, min(1.0, base))

    def _periodicity_score(
        self,
        cv: float,
        mean_interval: float,
        intervals: List[float],
    ) -> float:
        if not intervals or mean_interval <= 0:
            return 0.0

        # Robustness against a single outlier.
        within_20pct = sum(
            1 for x in intervals
            if abs(x - mean_interval) <= (0.20 * mean_interval)
        ) / float(len(intervals))

        cv_component = max(0.0, 1.0 - min(1.0, cv / 0.5))

        score = (0.60 * within_20pct) + (0.40 * cv_component)
        return max(0.0, min(1.0, score))

    # -------------------------------------------------------------------------
    # BEHAVIOR CLASSIFICATION
    # -------------------------------------------------------------------------

    def _classify_pattern(
        self,
        mean_interval: float,
        cv: float,
        burst_clusters: int,
        burst_ratio: float,
        periodicity_score: float,
    ) -> str:
        if burst_clusters >= 2 and burst_ratio >= 0.20:
            return "bursty"

        if mean_interval <= self.FAST_CONTINUOUS_INTERVAL_SEC and cv < 0.30:
            return "continuous"

        if periodicity_score >= 0.78 and cv <= self.PERIODIC_CV_THRESHOLD:
            return "periodic"

        if periodicity_score >= 0.58 and cv <= self.STABLE_CV_THRESHOLD:
            return "stable_intermittent"

        if cv >= self.IRREGULAR_CV_THRESHOLD:
            return "irregular"

        return "opportunistic"

    def _classify_subtype(
        self,
        mean_interval: float,
        cv: float,
        burst_clusters: int,
        burst_ratio: float,
        behavior_pattern: str,
        meta: List[Dict[str, Any]],
    ) -> str:
        protocol = (self._dominant_meta_value(meta, "protocol") or "").lower()

        if behavior_pattern == "continuous":
            if "wifi" in protocol or "802.11" in protocol:
                return "session_traffic"
            return "continuous_stream"

        if behavior_pattern == "periodic":
            if 0.08 <= mean_interval <= 0.15:
                return "beaconing"
            if self.LONG_TELEMETRY_MIN_SEC <= mean_interval <= self.LONG_TELEMETRY_MAX_SEC:
                return "scheduled_telemetry"
            return "fixed_interval_advertising"

        if behavior_pattern == "stable_intermittent":
            if self.SHORT_TELEMETRY_MIN_SEC <= mean_interval <= self.SHORT_TELEMETRY_MAX_SEC:
                return "low_rate_polling"
            return "stable_intervals"

        if behavior_pattern == "bursty":
            if burst_clusters >= 2 and mean_interval < 0.35:
                return "user_triggered_bursts"
            return "clustered_transmissions"

        if behavior_pattern == "irregular":
            if burst_ratio > 0.10:
                return "event_driven_activity"
            return "nonperiodic_chatter"

        return "mixed_activity"

    # -------------------------------------------------------------------------
    # DEVICE HINTS
    # -------------------------------------------------------------------------

    def _infer_device_hint(
        self,
        mean_interval: float,
        cv: float,
        burst_clusters: int,
        burst_ratio: float,
        behavior_pattern: str,
        behavior_subtype: str,
        meta: List[Dict[str, Any]],
    ) -> Optional[str]:
        """
        Conservative role hints only. This is intentionally not a product engine.
        """
        protocol = (self._dominant_meta_value(meta, "protocol") or "").lower()

        if behavior_subtype == "beaconing" and 0.08 <= mean_interval <= 0.15:
            if protocol == "ble":
                return "BLE Advertiser / Beacon Candidate"
            return "Periodic Beaconing Device Candidate"

        if behavior_subtype == "scheduled_telemetry":
            if protocol == "zigbee":
                return "Zigbee Telemetry Sensor Candidate"
            if protocol == "lora":
                return "LPWAN Telemetry Node Candidate"
            return "Scheduled Telemetry Device Candidate"

        if behavior_subtype == "user_triggered_bursts" and burst_clusters >= 2:
            return "Remote / User-Triggered Control Candidate"

        if behavior_pattern == "continuous":
            if "wifi" in protocol or "802.11" in protocol:
                return "High-Activity WiFi Node Candidate"
            return "Continuous RF Session Device Candidate"

        if behavior_subtype == "low_rate_polling":
            return "Low-Rate Sensor / Asset Tag Candidate"

        if behavior_pattern == "irregular" and cv >= 0.80 and burst_ratio < 0.10:
            return "Opportunistic / Event-Driven Endpoint Candidate"

        return None

    # -------------------------------------------------------------------------
    # CONFIDENCE / EXPLAINABILITY
    # -------------------------------------------------------------------------

    def _behavior_confidence(
        self,
        observation_count: int,
        stability_score: float,
        periodicity_score: float,
        behavior_pattern: str,
        burst_ratio: float,
        out_of_order_events: int,
    ) -> float:
        sample_score = min(1.0, observation_count / 20.0)

        confidence = (
            0.35 * sample_score +
            0.35 * stability_score +
            0.20 * periodicity_score +
            0.10 * (1.0 - min(1.0, burst_ratio))
        )

        if behavior_pattern == "bursty":
            # Bursty traffic is real, but harder to model confidently.
            confidence *= 0.90

        if behavior_pattern == "irregular":
            confidence *= 0.82

        if out_of_order_events > 0:
            confidence *= 0.92

        return max(0.0, min(1.0, confidence))

    def _build_behavior_tags(
        self,
        mean_interval: float,
        cv: float,
        burst_clusters: int,
        burst_ratio: float,
        periodicity_score: float,
        meta: List[Dict[str, Any]],
        behavior_pattern: str,
        behavior_subtype: str,
    ) -> List[str]:
        tags: List[str] = [behavior_pattern, behavior_subtype]

        protocol = self._dominant_meta_value(meta, "protocol")
        if protocol:
            tags.append(f"protocol:{str(protocol).lower()}")

        if periodicity_score >= 0.75:
            tags.append("high_periodicity")
        elif periodicity_score >= 0.55:
            tags.append("moderate_periodicity")

        if cv < 0.10:
            tags.append("high_stability")
        elif cv < 0.25:
            tags.append("moderate_stability")
        else:
            tags.append("variable_timing")

        if burst_clusters > 0:
            tags.append("burst_clusters_present")

        if burst_ratio >= 0.20:
            tags.append("burst_heavy")

        if mean_interval <= self.FAST_CONTINUOUS_INTERVAL_SEC:
            tags.append("fast_repeat_rate")
        elif mean_interval <= 0.20:
            tags.append("short_interval")
        elif mean_interval <= 3.0:
            tags.append("medium_interval")
        else:
            tags.append("long_interval")

        return tags

    def _build_reasoning(
        self,
        mean_interval: float,
        cv: float,
        burst_clusters: int,
        burst_ratio: float,
        periodicity_score: float,
        behavior_pattern: str,
        behavior_subtype: str,
        meta: List[Dict[str, Any]],
    ) -> List[str]:
        reasoning: List[str] = []

        reasoning.append(
            f"Mean inter-transmission interval is {round(mean_interval, 4)} seconds."
        )
        reasoning.append(
            f"Interval coefficient of variation is {round(cv, 4)}, indicating "
            f"{self._cv_label(cv)} timing regularity."
        )

        if periodicity_score >= 0.75:
            reasoning.append(
                "Interval distribution is strongly periodic across the observation window."
            )
        elif periodicity_score >= 0.55:
            reasoning.append(
                "Interval distribution shows moderate periodic structure."
            )
        else:
            reasoning.append(
                "Interval distribution does not show strong periodic structure."
            )

        if burst_clusters > 0:
            reasoning.append(
                f"Detected {burst_clusters} burst cluster(s) with burst ratio "
                f"{round(burst_ratio, 4)}."
            )

        reasoning.append(
            f"Behavior classified as '{behavior_pattern}' with subtype "
            f"'{behavior_subtype}'."
        )

        protocol = self._dominant_meta_value(meta, "protocol")
        if protocol:
            reasoning.append(
                f"Behavior interpretation was informed by upstream protocol hint '{protocol}'."
            )

        return reasoning

    # -------------------------------------------------------------------------
    # META AGGREGATION
    # -------------------------------------------------------------------------

    def _dominant_meta_value(
        self,
        meta: List[Dict[str, Any]],
        key: str,
    ) -> Optional[Any]:
        counts: Dict[Any, int] = {}
        for item in meta:
            value = item.get(key)
            if value is None:
                continue
            counts[value] = counts.get(value, 0) + 1

        if not counts:
            return None

        return max(counts.keys(), key=lambda k: counts[k])

    def _dominant_numeric_band(
        self,
        meta: List[Dict[str, Any]],
        key: str,
    ) -> Optional[float]:
        values = [self._safe_float(item.get(key), default=None) for item in meta]
        values = [v for v in values if v is not None]
        if not values:
            return None

        # Median is more robust than mean for sweep noise.
        return float(statistics.median(values))

    # -------------------------------------------------------------------------
    # UTILS
    # -------------------------------------------------------------------------

    def _first_present(self, data: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in data and data.get(key) is not None:
                return data.get(key)
        return None

    def _safe_float(self, value: Any, default: Optional[float] = 0.0) -> Optional[float]:
        try:
            if value is None:
                return default
            value = float(value)
            if math.isnan(value) or math.isinf(value):
                return default
            return value
        except Exception:
            return default

    def _cv_label(self, cv: float) -> str:
        if cv < 0.10:
            return "very high"
        if cv < 0.20:
            return "high"
        if cv < 0.35:
            return "moderate"
        if cv < 0.60:
            return "low"
        return "poor"
