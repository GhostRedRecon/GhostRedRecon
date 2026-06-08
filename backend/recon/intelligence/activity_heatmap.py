# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF ACTIVITY HEATMAP ENGINE
# FILE:         backend/recon/rf_activity_heatmap_engine.py
#
# VERSION:      v4.0.0 (PHASE-3 PERSISTENCE + HOTSPOT INTELLIGENCE UPGRADE)
# UPDATED:      2026-03-16
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is an RF reconnaissance and device intelligence platform built for
# red-team operations. This module builds a temporal persistence map of RF
# activity across the observed spectrum so the platform can distinguish:
#
# • stable infrastructure
# • recurring emitters
# • intermittent endpoints
# • short-lived trigger bursts
#
# The heatmap is not a detector by itself. It is a persistence intelligence
# layer that enriches emitter observations and helps upstream scheduling,
# behavior analysis, and device inference.
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# PeakDetector
#     ↓
# BurstDetector
#     ↓
# EmitterCluster
#     ↓
# EmitterTracker
#     ↓
# RFActivityHeatmapEngine   ← THIS MODULE
#     ↓
# RFBehaviorEngine
#     ↓
# Device Intelligence
#     ↓
# Adaptive RF Sweep Controller
#
#
# FUNCTIONAL MODEL
# -----------------------------------------------------------------------------
# emitter observations
#     ↓
# frequency normalization
#     ↓
# bucket scoring
#     ↓
# weighted persistence accumulation
#     ↓
# time-based decay
#     ↓
# hotspot classification
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. TEMPORAL RF MAPPING
# -----------------------------------------------------------------------------
# Signals must be evaluated over time, not as isolated events.
#
#
# 2. WEIGHTED PERSISTENCE
# -----------------------------------------------------------------------------
# Stronger and more stable observations should contribute more heat than weak
# or ambiguous observations.
#
#
# 3. BOUNDED MEMORY
# -----------------------------------------------------------------------------
# The engine tracks bucketed activity only and expires stale buckets.
#
#
# 4. SCHEMA TOLERANCE
# -----------------------------------------------------------------------------
# The engine accepts mixed emitter schemas from evolving upstream modules.
#
#
# 5. OPERATIONAL USEFULNESS
# -----------------------------------------------------------------------------
# Output must help channel prioritization, infrastructure identification, and
# real-time debugging.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • tracking RF activity persistence
# • building weighted frequency heatmaps
# • identifying hotspots and recency state
# • enriching emitters with activity metadata
# • exposing heatmap state for orchestration
#
#
# This module is NOT responsible for:
#
# • RF detection
# • demodulation
# • protocol classification
# • SDR control
#
# =============================================================================

from __future__ import annotations

import logging
import math
import time
from typing import Any, Dict, List, Optional


logger = logging.getLogger("ghostrecon.rf_heatmap")


class RFActivityHeatmapEngine:
    VERSION = "4.0.0"

    MAX_SCORE = 100.0
    BUCKET_SIZE_MHZ = 1.0

    DECAY_INTERVAL_SEC = 2.0
    DECAY_PER_SEC = 0.85
    STALE_TIMEOUT_SEC = 45.0

    PERSISTENT_THRESHOLD = 42.0
    INTERMITTENT_THRESHOLD = 12.0
    ACTIVE_HOTSPOT_THRESHOLD = 20.0

    MAX_HOTSPOTS_RETURN = 50

    # ---------------------------------------------------------------------

    def __init__(self) -> None:
        self.activity_map: Dict[float, Dict[str, Any]] = {}
        self._last_decay_ts = time.time()

    # ---------------------------------------------------------------------
    # PUBLIC UPDATE
    # ---------------------------------------------------------------------

    def update(self, emitters: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if not emitters:
            self._decay(time.time())
            return emitters or []

        now = time.time()

        for emitter in emitters:
            try:
                freq = self._extract_frequency_mhz(emitter)
                if freq is None:
                    continue

                bucket = self._bucketize(freq)
                bucket_state = self._get_or_create_bucket(bucket, now)

                increment = self._compute_increment(emitter)

                old_score = bucket_state["score"]
                new_score = min(self.MAX_SCORE, old_score + increment)

                bucket_state["score"] = new_score
                bucket_state["peak_score"] = max(bucket_state["peak_score"], new_score)
                bucket_state["hits"] += 1
                bucket_state["last_seen"] = now

                bucket_state["protocols"].add(self._safe_text(
                    emitter.get("rf_protocol") or emitter.get("protocol")
                ))
                bucket_state["classes"].add(self._safe_text(
                    emitter.get("rf_activity_class")
                ))

                if emitter.get("rf_emitter_id"):
                    bucket_state["emitters"].add(str(emitter["rf_emitter_id"]))

                self._annotate_emitter(emitter, bucket, bucket_state, increment, now)

            except Exception as exc:
                logger.debug("Heatmap update error: %s", exc)

        self._decay(now)
        return emitters

    # ---------------------------------------------------------------------
    # HOTSPOTS
    # ---------------------------------------------------------------------

    def get_hotspots(
        self,
        threshold: float = ACTIVE_HOTSPOT_THRESHOLD,
        limit: int = MAX_HOTSPOTS_RETURN,
    ) -> List[Dict[str, Any]]:
        now = time.time()
        self._decay(now)

        results: List[Dict[str, Any]] = []

        for freq, state in self.activity_map.items():
            score = state["score"]

            if score < threshold:
                continue

            results.append({
                "freq_mhz": freq,
                "activity_score": round(score, 3),
                "peak_score": round(state["peak_score"], 3),
                "persistence": self._classify(score),
                "recency": self._recency_class(now - state["last_seen"]),
                "hits": state["hits"],
                "unique_emitters": len(state["emitters"]),
                "age_sec": round(now - state["first_seen"], 3),
                "last_seen_sec_ago": round(now - state["last_seen"], 3),
                "protocols": sorted([p for p in state["protocols"] if p]),
            })

        results.sort(
            key=lambda x: (
                x["activity_score"],
                x["unique_emitters"],
                -x["last_seen_sec_ago"],
            ),
            reverse=True,
        )

        return results[:max(1, int(limit))]

    # ---------------------------------------------------------------------
    # STATE
    # ---------------------------------------------------------------------

    def state(self) -> Dict[str, Any]:
        now = time.time()
        self._decay(now)

        persistent = 0
        intermittent = 0
        rare = 0

        for state in self.activity_map.values():
            label = self._classify(state["score"])
            if label == "persistent":
                persistent += 1
            elif label == "intermittent":
                intermittent += 1
            else:
                rare += 1

        hotspots = self.get_hotspots(threshold=self.ACTIVE_HOTSPOT_THRESHOLD, limit=10)

        return {
            "version": self.VERSION,
            "tracked_freq": len(self.activity_map),
            "persistent_buckets": persistent,
            "intermittent_buckets": intermittent,
            "rare_buckets": rare,
            "active_hotspots": len(hotspots),
            "top_hotspots": hotspots,
            "bucket_size_mhz": self.BUCKET_SIZE_MHZ,
            "max_score": self.MAX_SCORE,
            "decay_per_sec": self.DECAY_PER_SEC,
            "stale_timeout_sec": self.STALE_TIMEOUT_SEC,
        }

    # ---------------------------------------------------------------------
    # INTERNAL: EMITTER ANNOTATION
    # ---------------------------------------------------------------------

    def _annotate_emitter(
        self,
        emitter: Dict[str, Any],
        bucket: float,
        bucket_state: Dict[str, Any],
        increment: float,
        now: float,
    ) -> None:
        score = bucket_state["score"]

        emitter["rf_activity_bucket_mhz"] = bucket
        emitter["rf_activity_score"] = round(score, 3)
        emitter["rf_activity_peak_score"] = round(bucket_state["peak_score"], 3)
        emitter["rf_activity_increment"] = round(increment, 3)
        emitter["rf_activity_hits"] = bucket_state["hits"]
        emitter["rf_activity_class"] = self._classify(score)
        emitter["rf_activity_recency"] = self._recency_class(now - bucket_state["last_seen"])
        emitter["rf_activity_unique_emitters"] = len(bucket_state["emitters"])

    # ---------------------------------------------------------------------
    # INTERNAL: SCORING
    # ---------------------------------------------------------------------

    def _compute_increment(self, emitter: Dict[str, Any]) -> float:
        score = 1.0

        hit_count = self._to_float(
            emitter.get("hit_count") or emitter.get("rf_hit_count"),
            default=1.0,
        )
        if hit_count > 1:
            score += min(1.5, math.log1p(hit_count) * 0.45)

        protocol_conf = self._to_float(
            emitter.get("protocol_confidence") or emitter.get("rf_protocol_confidence"),
            default=0.0,
        )
        score += min(0.8, max(0.0, protocol_conf) * 0.6)

        emitter_hits = self._to_float(
            emitter.get("emitter_hits") or emitter.get("rf_emitter_hits"),
            default=0.0,
        )
        if emitter_hits > 0:
            score += min(0.8, math.log1p(emitter_hits) * 0.22)

        power_db = self._to_float(
            emitter.get("power_db") or emitter.get("rf_power_db"),
            default=None,
        )
        if power_db is not None:
            if power_db >= 20:
                score += 0.8
            elif power_db >= 10:
                score += 0.5
            elif power_db >= 0:
                score += 0.25

        state = self._safe_text(emitter.get("emitter_state"))
        if state == "persistent":
            score += 0.9
        elif state == "stable":
            score += 0.45

        behavior = self._safe_text(
            emitter.get("rf_behavior_pattern") or emitter.get("behavior_pattern")
        )
        if behavior in {"highly_periodic", "periodic"}:
            score += 0.35
        elif behavior == "burst":
            score += 0.10

        bandwidth = self._to_float(
            emitter.get("bandwidth_mhz") or emitter.get("rf_bandwidth_mhz"),
            default=0.0,
        )
        if bandwidth >= 10.0:
            score += 0.35
        elif bandwidth >= 2.0:
            score += 0.15

        return max(0.25, min(4.0, score))

    # ---------------------------------------------------------------------
    # INTERNAL: DECAY
    # ---------------------------------------------------------------------

    def _decay(self, now: float) -> None:
        elapsed_since_decay = now - self._last_decay_ts
        if elapsed_since_decay < self.DECAY_INTERVAL_SEC:
            return

        self._last_decay_ts = now

        expired: List[float] = []

        for freq, state in self.activity_map.items():
            idle = now - state["last_seen"]

            if idle >= self.STALE_TIMEOUT_SEC:
                expired.append(freq)
                continue

            decay_amount = idle * self.DECAY_PER_SEC
            state["score"] = max(0.0, state["score"] - decay_amount)

            if state["score"] <= 0.05:
                expired.append(freq)

        for freq in expired:
            self.activity_map.pop(freq, None)

    # ---------------------------------------------------------------------
    # INTERNAL: BUCKET MANAGEMENT
    # ---------------------------------------------------------------------

    def _get_or_create_bucket(self, bucket: float, now: float) -> Dict[str, Any]:
        state = self.activity_map.get(bucket)
        if state is not None:
            return state

        state = {
            "score": 0.0,
            "peak_score": 0.0,
            "hits": 0,
            "first_seen": now,
            "last_seen": now,
            "emitters": set(),
            "protocols": set(),
            "classes": set(),
        }
        self.activity_map[bucket] = state
        return state

    def _bucketize(self, freq_mhz: float) -> float:
        return round(freq_mhz / self.BUCKET_SIZE_MHZ) * self.BUCKET_SIZE_MHZ

    # ---------------------------------------------------------------------
    # INTERNAL: LABELS
    # ---------------------------------------------------------------------

    def _classify(self, score: float) -> str:
        if score >= self.PERSISTENT_THRESHOLD:
            return "persistent"
        if score >= self.INTERMITTENT_THRESHOLD:
            return "intermittent"
        return "rare"

    def _recency_class(self, age_sec: float) -> str:
        if age_sec <= 3:
            return "hot"
        if age_sec <= 10:
            return "warm"
        if age_sec <= 20:
            return "cooling"
        return "stale"

    # ---------------------------------------------------------------------
    # INTERNAL: NORMALIZATION
    # ---------------------------------------------------------------------

    def _extract_frequency_mhz(self, emitter: Dict[str, Any]) -> Optional[float]:
        freq = (
            emitter.get("freq_mhz")
            or emitter.get("rf_frequency_mhz")
            or emitter.get("frequency_mhz")
            or emitter.get("center_freq_mhz")
        )
        return self._to_float(freq, default=None)

    def _safe_text(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().lower()
        return text or None

    def _to_float(self, value: Any, default: Optional[float] = 0.0) -> Optional[float]:
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default
