# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       BLE DEVICE INTELLIGENCE ENGINE
# FILE:         backend/recon/intelligence/ble_device_intelligence.py
#
# VERSION:      v1.0.0 (PHASE-3 BLE ROLE / PRODUCT INTELLIGENCE)
# UPDATED:      2026-03-16
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RF Recon Pipeline
#
# HackRF SDR
#     ↓
# LiveFFT / Spectral Processing
#     ↓
# Peak / Burst Detection
#     ↓
# Emitter Tracking / Lifecycle
#     ↓
# Feature Extraction
#     ↓
# RF Protocol Fingerprint Engine
#     ↓
# RF Protocol Classifier
#     ↓
# BLEDeviceIntelligenceEngine        ← THIS MODULE
#     ↓
# RFDeviceFusionEngine
#     ↓
# Device Intelligence / Product Inference / Attack Surface Mapping
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance and red-team intelligence platform.
#
# This module transforms protocol-level BLE observations into higher-level,
# device-oriented intelligence. It does NOT decode BLE payloads. Instead, it
# uses explainable RF-side heuristics, temporal behavior, signal shape clues,
# frequency/channel alignment, and upstream classifier hints to estimate:
#
#   • BLE role / archetype
#   • behavior profile
#   • probable device category
#   • confidence and evidence quality
#   • whether the signal resembles advertising-oriented BLE activity
#   • whether the emitter looks more like infrastructure, wearable, audio,
#     tracker, sensor, lock/accessory, or phone-class behavior
#
# The goal is to improve:
#
#   • device fusion quality
#   • device graph correlation
#   • red-team targeting context
#   • product / vendor attribution readiness
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PASSIVE-ONLY INTELLIGENCE
# -----------------------------------------------------------------------------
# No packet decoding assumptions. This engine must work from RF-side metadata
# and protocol classifier outputs only.
#
# 2. EXPLAINABLE DECISIONS
# -----------------------------------------------------------------------------
# Every role/category estimate carries evidence, negative evidence, confidence,
# and reasoning state.
#
# 3. FALSE-POSITIVE RESISTANT
# -----------------------------------------------------------------------------
# Unknown BLE peripheral is safer than confidently wrong product claims.
#
# 4. DOWNSTREAM READY
# -----------------------------------------------------------------------------
# Output must be directly consumable by:
#   • device_fusion.py
#   • device_intelligence.py
#   • frontend / intelligence APIs
#
# 5. SCHEMA-TOLERANT
# -----------------------------------------------------------------------------
# Must tolerate evolving upstream feature schemas and mixed naming conventions.
#
# 6. REAL-TIME SAFE
# -----------------------------------------------------------------------------
# Lightweight, bounded, deterministic logic suitable for continuous recon.
#
# 7. ROLE-FIRST, BRAND-LATER
# -----------------------------------------------------------------------------
# This engine should estimate device role/archetype first. Exact product/vendor
# attribution belongs to later fusion and intelligence layers.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# BLEDeviceIntelligenceEngine IS responsible for:
#
#   • identifying BLE-like emitter behavior from normalized feature records
#   • estimating BLE operating mode hints (advertising-like / bursty / roaming)
#   • assigning probable BLE device role hypotheses
#   • producing ranked BLE category candidates
#   • exporting explainable evidence and confidence fields
#   • emitting fusion-friendly intelligence fields
#
# BLEDeviceIntelligenceEngine is NOT responsible for:
#
#   • SDR control
#   • packet decoding
#   • raw demodulation
#   • vendor lookup databases
#   • final device fusion
#   • exact product attribution
#
# =============================================================================

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger("ghostrecon.ble_device_intelligence")


class BLEDeviceIntelligenceEngine:
    """
    Production BLE intelligence engine for passive RF-side role inference.

    Input:
        emitter dicts enriched by:
          - protocol_classifier
          - feature_extractor
          - tracker / lifecycle
          - protocol_fingerprint engine

    Output:
        emitter dicts augmented with BLE intelligence fields suitable for
        fusion, device intelligence, and UI/API export.
    """

    VERSION = "1.0.0"

    BLE_ADV_CHANNELS_MHZ = [2402.0, 2426.0, 2480.0]

    # Minimum protocol confidence before treating emitter as BLE-relevant
    MIN_BLE_PROTOCOL_CONFIDENCE = 0.30

    # Candidate threshold for export
    MIN_ROLE_EXPORT_SCORE = 0.20
    MIN_DECODED_PRODUCT_EVIDENCE = 0.45

    def enrich_emitters(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched: List[Dict[str, Any]] = []

        for emitter in emitters or []:
            try:
                enriched.append(self._enrich_single(emitter))
            except Exception as exc:
                logger.exception("BLE intelligence error: %s", exc)
                enriched.append(
                    self._fallback(
                        emitter,
                        reason=f"ble_intelligence_exception:{exc.__class__.__name__}"
                    )
                )

        return enriched

    # -------------------------------------------------------------------------
    # CORE
    # -------------------------------------------------------------------------

    def _enrich_single(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        emitter = dict(emitter or {})
        f = self._normalize(emitter)

        protocol = f["rf_protocol"]
        protocol_conf = f["protocol_confidence"]

        ble_relevant = (
            protocol in {"ble", "bluetooth_low_energy", "bluetooth", "bluetooth_le"}
            or (
                protocol == "unknown_rf"
                and (
                    f["ble_dist"] is not None
                    and f["ble_dist"] <= 3.0
                    and f["rf_band"] == "2.4ghz"
                )
            )
        )

        if not ble_relevant or (
            protocol == "ble" and protocol_conf < self.MIN_BLE_PROTOCOL_CONFIDENCE
        ):
            return self._annotate_non_ble(emitter, f)

        mode = self._estimate_operating_mode(f)

        candidates = [
            self._score_advertising_flood(f, mode),
            self._score_beacon(f, mode),
            self._score_tracker(f, mode),
            self._score_wearable(f, mode),
            self._score_audio_device(f, mode),
            self._score_smart_lock_or_access_control(f, mode),
            self._score_sensor_tag(f, mode),
            self._score_phone_or_computing_device(f, mode),
            self._score_infrastructure_or_gateway(f, mode),
            self._score_unknown_ble_peripheral(f, mode),
        ]
        candidates = sorted(candidates, key=lambda x: x["score"], reverse=True)

        best = candidates[0] if candidates else self._empty_candidate()
        second = candidates[1] if len(candidates) > 1 else self._empty_candidate()

        margin = max(best["score"] - second["score"], 0.0)
        ambiguous = best["score"] >= 0.35 and second["score"] >= 0.30 and margin < 0.10

        confidence = self._shape_confidence(
            best_score=best["score"],
            second_score=second["score"],
            margin=margin,
            readiness=f["readiness"],
            completeness=f["completeness"],
            stability=f["stability"],
            negative_count=len(best["negative_evidence"]),
            ambiguous=ambiguous,
        )
        decoded_evidence_score = f["decoded_evidence_score"]
        if decoded_evidence_score < self.MIN_DECODED_PRODUCT_EVIDENCE:
            confidence = min(confidence, 0.49)

        decision_state = self._decision_state(
            best_score=best["score"],
            second_score=second["score"],
            margin=margin,
            readiness=f["readiness"],
            completeness=f["completeness"],
            stability=f["stability"],
            ambiguous=ambiguous,
        )

        category = best["role"] if confidence >= 0.40 else "unknown_ble_peripheral"
        confidence = round(confidence, 4)

        emitter["ble_intel_version"] = self.VERSION
        emitter["ble_intelligence_ready"] = True
        emitter["ble_relevant"] = True
        emitter["ble_operating_mode_hint"] = mode
        emitter["ble_role"] = category
        emitter["ble_role_confidence"] = confidence
        emitter["ble_role_secondary"] = (
            second["role"] if second["score"] >= self.MIN_ROLE_EXPORT_SCORE else None
        )
        emitter["ble_role_secondary_confidence"] = round(
            second["score"] if second["score"] >= self.MIN_ROLE_EXPORT_SCORE else 0.0,
            4,
        )

        emitter["ble_role_margin"] = round(margin, 4)
        emitter["ble_role_ambiguous"] = bool(ambiguous)
        emitter["ble_decision_state"] = decision_state
        emitter["ble_decision_quality"] = self._decision_quality(
            confidence=confidence,
            margin=margin,
            readiness=f["readiness"],
            ambiguous=ambiguous,
        )

        emitter["ble_evidence"] = list(best["evidence"])
        emitter["ble_negative_evidence"] = list(best["negative_evidence"])
        emitter["ble_observability"] = self._observability_label(
            readiness=f["readiness"],
            completeness=f["completeness"],
            stability=f["stability"],
        )

        emitter["ble_adv_channel_distance_mhz"] = f["ble_dist"]
        emitter["ble_adv_like"] = bool(f["adv_like"])
        emitter["ble_periodic_like"] = bool(f["periodic_like"])
        emitter["ble_mobile_like"] = bool(f["mobile_like"])
        emitter["ble_stationary_like"] = bool(f["stationary_like"])
        emitter["ble_decoded_evidence_score"] = round(decoded_evidence_score, 4)
        emitter["ble_identity_basis"] = "decoded" if decoded_evidence_score >= self.MIN_DECODED_PRODUCT_EVIDENCE else "rf_only"

        emitter["ble_category_candidates"] = [
            {
                "role": c["role"],
                "score": round(c["score"], 4),
                "confidence_hint": round(
                    self._candidate_confidence_hint(
                        c["score"],
                        margin if c is best else 0.0,
                    ),
                    4,
                ),
                "evidence_count": len(c["evidence"]),
                "negative_evidence_count": len(c["negative_evidence"]),
                "top_evidence": list(c["evidence"][:5]),
            }
            for c in candidates
            if c["score"] >= self.MIN_ROLE_EXPORT_SCORE
        ]

        # fusion-friendly aliases
        emitter["device_role_hint"] = emitter["ble_role"]
        emitter["device_role_confidence"] = emitter["ble_role_confidence"]
        if decoded_evidence_score >= self.MIN_DECODED_PRODUCT_EVIDENCE:
            emitter["product_category_hint"] = self._map_role_to_product_category(
                emitter["ble_role"]
            )
            emitter["product_category_confidence"] = round(
                confidence * 0.92 if emitter["ble_role"] != "unknown_ble_peripheral" else 0.0,
                4,
            )
        else:
            emitter["product_category_hint"] = None
            emitter["product_category_confidence"] = 0.0
        emitter["behavior_profile_hint"] = self._map_mode_to_behavior_profile(mode)
        emitter["rf_device_class"] = (
            self._map_role_to_rf_device_class(emitter["ble_role"])
            if decoded_evidence_score >= self.MIN_DECODED_PRODUCT_EVIDENCE
            else "ble_unknown"
        )

        return emitter

    # -------------------------------------------------------------------------
    # NORMALIZATION
    # -------------------------------------------------------------------------

    def _normalize(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        freq = self._f(
            emitter.get("rf_frequency_mhz"),
            emitter.get("freq_mhz"),
            emitter.get("frequency_mhz"),
        )

        bw = self._f(
            emitter.get("rf_bandwidth_mhz"),
            emitter.get("bandwidth_mhz"),
            emitter.get("rf_bandwidth_est_mhz"),
            default=0.0,
        ) or 0.0

        protocol = self._norm_protocol(
            emitter.get("rf_protocol"),
            emitter.get("protocol"),
        ) or "unknown_rf"

        protocol_confidence = self._f(
            emitter.get("rf_protocol_confidence"),
            emitter.get("protocol_confidence"),
            emitter.get("confidence"),
            default=0.0,
        ) or 0.0

        readiness = self._f(
            emitter.get("rf_classifier_readiness"),
            emitter.get("rf_protocol_readiness"),
            emitter.get("protocol_readiness"),
            default=0.0,
        ) or 0.0

        completeness = self._f(
            emitter.get("rf_feature_completeness"),
            default=0.0,
        ) or 0.0

        stability = self._f(
            emitter.get("rf_signal_stability"),
            emitter.get("rf_stability_score"),
            default=0.0,
        ) or 0.0

        burst_periodicity = self._f(
            emitter.get("rf_burst_periodicity"),
            emitter.get("burst_periodicity"),
        )

        burst_duration = self._f(
            emitter.get("rf_burst_duration"),
            emitter.get("burst_duration"),
        )

        duty_cycle = self._f(
            emitter.get("rf_duty_cycle"),
            default=0.0,
        ) or 0.0

        temporal_profile = self._s(
            emitter.get("rf_temporal_profile"),
            emitter.get("temporal_profile"),
        )

        signal_class = self._s(
            emitter.get("rf_signal_class"),
            emitter.get("signal_class"),
        )

        modulation_hint = self._s(
            emitter.get("rf_modulation_hint"),
            emitter.get("modulation"),
        )

        nearest_family = self._s(
            emitter.get("rf_nearest_channel_family"),
            emitter.get("channel_family"),
        )

        if nearest_family == "ble_adv":
            nearest_family = "ble"

        ble_dist = self._f(
            emitter.get("rf_ble_adv_distance_mhz"),
            emitter.get("ble_adv_channel_distance_mhz"),
        )
        explicit_ble_channel = self._i(
            emitter.get("ble_channel"),
            emitter.get("channel") if self._s(emitter.get("channel_family")) == "ble" else None,
        )
        if ble_dist is None and freq is not None:
            ble_dist = min(abs(freq - x) for x in self.BLE_ADV_CHANNELS_MHZ)
        if explicit_ble_channel in {37, 38, 39}:
            ble_dist = 0.0 if ble_dist is None else min(ble_dist, 0.0)

        rf_band = self._norm_band(
            emitter.get("rf_band"),
            self._detect_band(freq),
        )

        emitter_state = self._s(
            emitter.get("rf_emitter_state"),
            emitter.get("emitter_state"),
        )

        continuity = self._f(
            emitter.get("rf_identity_continuity_score"),
            default=0.0,
        ) or 0.0

        observation_count = self._i(
            emitter.get("rf_observation_count"),
            emitter.get("observation_count"),
            default=0,
        )
        signal_count = self._i(
            emitter.get("signal_count"),
            default=0,
        )
        burst_recurrence_score = self._f(
            emitter.get("burst_recurrence_score"),
            default=0.0,
        ) or 0.0
        channel_confidence = self._f(
            emitter.get("channel_confidence"),
            default=0.0,
        ) or 0.0

        signals = emitter.get("signals") if isinstance(emitter.get("signals"), list) else []
        if signals:
            best_signal = max(
                (signal for signal in signals if isinstance(signal, dict)),
                key=lambda signal: self._f(signal.get("confidence"), default=0.0) or 0.0,
                default=None,
            )
            if best_signal:
                protocol = self._norm_protocol(
                    emitter.get("rf_protocol"),
                    emitter.get("protocol"),
                    best_signal.get("rf_protocol"),
                    best_signal.get("protocol"),
                ) or "unknown_rf"
                protocol_confidence = self._f(
                    emitter.get("rf_protocol_confidence"),
                    emitter.get("protocol_confidence"),
                    best_signal.get("rf_protocol_confidence"),
                    best_signal.get("protocol_confidence"),
                    best_signal.get("confidence"),
                    default=0.0,
                ) or 0.0
                if explicit_ble_channel is None:
                    explicit_ble_channel = self._i(best_signal.get("ble_channel"))
                if explicit_ble_channel in {37, 38, 39}:
                    ble_dist = 0.0
                nearest_family = self._s(nearest_family, best_signal.get("channel_family"))
                duty_cycle = self._f(
                    emitter.get("rf_duty_cycle"),
                    best_signal.get("rf_duty_cycle"),
                    best_signal.get("burst_ratio"),
                    default=0.0,
                ) or 0.0
                burst_periodicity = self._f(
                    emitter.get("rf_burst_periodicity"),
                    best_signal.get("rf_burst_periodicity"),
                    best_signal.get("periodicity"),
                )
                temporal_profile = self._s(
                    emitter.get("rf_temporal_profile"),
                    best_signal.get("rf_temporal_profile"),
                    best_signal.get("signal_type"),
                )
                signal_class = self._s(
                    emitter.get("rf_signal_class"),
                    best_signal.get("rf_signal_class"),
                )
                stability = self._f(
                    emitter.get("rf_signal_stability"),
                    best_signal.get("signal_stability"),
                    default=0.0,
                ) or 0.0
                observation_count = max(
                    observation_count,
                    self._i(best_signal.get("updates"), best_signal.get("hit_count"), default=0),
                )
                burst_recurrence_score = max(
                    burst_recurrence_score,
                    self._f(best_signal.get("burst_recurrence_score"), default=0.0) or 0.0,
                )
                channel_confidence = max(
                    channel_confidence,
                    self._f(best_signal.get("channel_confidence"), default=0.0) or 0.0,
                )

        adv_like = self._estimate_adv_like(
            ble_dist=ble_dist,
            ble_channel=explicit_ble_channel,
            channel_confidence=channel_confidence,
            bw=bw,
            duty_cycle=duty_cycle,
            burst_periodicity=burst_periodicity,
            burst_recurrence_score=burst_recurrence_score,
            temporal_profile=temporal_profile,
            signal_class=signal_class,
            modulation_hint=modulation_hint,
            nearest_family=nearest_family,
        )

        periodic_like = self._estimate_periodic_like(
            burst_periodicity=burst_periodicity,
            temporal_profile=temporal_profile,
            duty_cycle=duty_cycle,
        )

        mobile_like = self._estimate_mobile_like(
            continuity=continuity,
            emitter_state=emitter_state,
            temporal_profile=temporal_profile,
            stability=stability,
            duty_cycle=duty_cycle,
        )

        stationary_like = self._estimate_stationary_like(
            continuity=continuity,
            emitter_state=emitter_state,
            temporal_profile=temporal_profile,
            stability=stability,
            duty_cycle=duty_cycle,
            observation_count=observation_count,
        )

        freq_span_mhz = self._signal_span(signals)
        dense_cluster_like = self._estimate_dense_cluster_like(
            linked_signal_count=len(signals),
            observation_count=observation_count,
            freq_span_mhz=freq_span_mhz,
            duty_cycle=duty_cycle,
        )
        flood_like = self._estimate_flood_like(
            linked_signal_count=len(signals),
            observation_count=observation_count,
            freq_span_mhz=freq_span_mhz,
            duty_cycle=duty_cycle,
            adv_like=adv_like,
            temporal_profile=temporal_profile,
        )

        return {
            "freq": freq,
            "bw": bw,
            "rf_protocol": protocol,
            "protocol_confidence": protocol_confidence,
            "readiness": readiness,
            "completeness": completeness,
            "stability": stability,
            "burst_periodicity": burst_periodicity,
            "burst_duration": burst_duration,
            "duty_cycle": duty_cycle,
            "temporal_profile": temporal_profile,
            "signal_class": signal_class,
            "modulation_hint": modulation_hint,
            "nearest_family": nearest_family,
            "ble_dist": ble_dist,
            "rf_band": rf_band,
            "emitter_state": emitter_state,
            "continuity": continuity,
            "observation_count": observation_count,
            "signal_count": signal_count,
            "linked_signal_count": len(signals),
            "freq_span_mhz": freq_span_mhz,
            "channel_confidence": channel_confidence,
            "ble_channel": explicit_ble_channel,
            "burst_recurrence_score": burst_recurrence_score,
            "dense_cluster_like": dense_cluster_like,
            "flood_like": flood_like,
            "adv_like": adv_like,
            "periodic_like": periodic_like,
            "mobile_like": mobile_like,
            "stationary_like": stationary_like,
            "decoded_evidence_score": self._decoded_evidence_score(emitter, signals),
        }

    def _decoded_evidence_score(self, emitter: Dict[str, Any], signals: List[Dict[str, Any]]) -> float:
        score = 0.0
        service_uuids = emitter.get("service_uuids") or []
        service_data = emitter.get("service_data") or {}
        if emitter.get("mac_address"):
            score += 0.28
        if emitter.get("manufacturer_id"):
            score += 0.26
        if emitter.get("device_name"):
            score += 0.24
        if service_uuids:
            score += 0.18
        if service_data:
            score += 0.16
        if emitter.get("appearance") is not None:
            score += 0.10
        if emitter.get("ble_payload"):
            score += 0.10
        if any((signal or {}).get("mac_address") for signal in signals):
            score += 0.12
        return self._clamp(score, 0.0, 1.0)

    # -------------------------------------------------------------------------
    # MODE ESTIMATION
    # -------------------------------------------------------------------------

    def _estimate_operating_mode(self, f: Dict[str, Any]) -> str:
        if f["flood_like"]:
            return "flooded_advertising"
        if f["adv_like"] and f["periodic_like"] and f["stationary_like"]:
            return "advertising_stationary"
        if f["adv_like"] and f["mobile_like"]:
            return "advertising_mobile"
        if f["adv_like"]:
            return "advertising_general"
        if f["mobile_like"]:
            return "mobile_interactive"
        if f["stationary_like"]:
            return "stationary_interactive"
        return "undifferentiated_ble"

    # -------------------------------------------------------------------------
    # ROLE SCORING
    # -------------------------------------------------------------------------

    def _score_advertising_flood(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["flood_like"]:
            score += 0.32
            ev.append("flood_like")

        if f["dense_cluster_like"]:
            score += 0.16
            ev.append("dense_cluster_like")

        if f["adv_like"]:
            score += 0.12
            ev.append("adv_like")

        if f["linked_signal_count"] >= 8:
            score += 0.12
            ev.append("linked_signal_count>=8")
        elif f["linked_signal_count"] >= 5:
            score += 0.06
            ev.append("linked_signal_count>=5")

        if f["freq_span_mhz"] >= 1.0:
            score += 0.10
            ev.append("freq_span>=1.0MHz")

        if f["duty_cycle"] >= 0.40:
            score += 0.10
            ev.append("high_duty_cycle")

        if f["observation_count"] >= 20:
            score += 0.08
            ev.append("observation_count>=20")

        if mode == "flooded_advertising":
            score += 0.12
            ev.append("mode=flooded_advertising")

        if f["stationary_like"] and not f["dense_cluster_like"]:
            neg.append("simple_stationary_pattern_reduces_flood_confidence")

        return self._candidate("ble_advertising_flood", score, ev, neg)

    def _score_beacon(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["adv_like"]:
            score += 0.22
            ev.append("adv_like")

        if f["periodic_like"]:
            score += 0.18
            ev.append("periodic_like")

        if f["stationary_like"]:
            score += 0.12
            ev.append("stationary_like")

        if f["ble_dist"] is not None and f["ble_dist"] <= 1.5:
            score += 0.14
            ev.append("near_ble_adv_channel<=1.5MHz")

        if 0.3 <= f["bw"] <= 2.5:
            score += 0.08
            ev.append("bandwidth_ble_like")

        if f["duty_cycle"] <= 0.18:
            score += 0.08
            ev.append("low_duty_cycle")

        if mode == "advertising_stationary":
            score += 0.08
            ev.append("mode=advertising_stationary")

        if f["flood_like"]:
            score -= 0.18
            neg.append("flood_like_conflicts_with_simple_beacon")
        if f["linked_signal_count"] >= 8:
            score -= 0.10
            neg.append("too_many_linked_signals_for_simple_beacon")

        if f["mobile_like"]:
            neg.append("mobile_like_conflicts_with_beacon")

        if f["duty_cycle"] >= 0.45:
            neg.append("high_duty_cycle_conflicts_with_simple_beacon")

        return self._candidate("beacon", score, ev, neg)

    def _score_tracker(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["adv_like"]:
            score += 0.18
            ev.append("adv_like")

        if f["periodic_like"]:
            score += 0.10
            ev.append("periodic_like")

        if f["mobile_like"]:
            score += 0.16
            ev.append("mobile_like")

        if f["stability"] < 0.55:
            score += 0.08
            ev.append("moderate_or_low_stability")

        if f["duty_cycle"] <= 0.22:
            score += 0.06
            ev.append("low_duty_cycle")

        if mode == "advertising_mobile":
            score += 0.10
            ev.append("mode=advertising_mobile")

        if f["flood_like"]:
            score -= 0.28
            neg.append("flood_like_conflicts_with_tracker")
        if f["linked_signal_count"] >= 8:
            score -= 0.12
            neg.append("too_many_linked_signals_for_tracker")
        if f["freq_span_mhz"] >= 1.0:
            score -= 0.08
            neg.append("wide_freq_span_conflicts_with_tracker")

        if f["stationary_like"]:
            neg.append("stationary_like_reduces_tracker_confidence")

        return self._candidate("tracker_tag", score, ev, neg)

    def _score_wearable(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["adv_like"]:
            score += 0.16
            ev.append("adv_like")

        if f["mobile_like"]:
            score += 0.16
            ev.append("mobile_like")

        if f["periodic_like"]:
            score += 0.08
            ev.append("periodic_like")

        if 0.05 <= (f["burst_periodicity"] or 0.0) <= 1.50:
            score += 0.08
            ev.append("burst_periodicity_wearable_like")

        if f["duty_cycle"] <= 0.28:
            score += 0.05
            ev.append("moderate_low_duty_cycle")

        if f["temporal_profile"] in {"periodic", "intermittent", "bursty"}:
            score += 0.05
            ev.append(f"temporal_profile={f['temporal_profile']}")

        if mode == "advertising_mobile":
            score += 0.08
            ev.append("mode=advertising_mobile")

        if f["flood_like"]:
            score -= 0.22
            neg.append("flood_like_conflicts_with_wearable")
        if f["linked_signal_count"] >= 8:
            score -= 0.08
            neg.append("too_many_linked_signals_for_simple_wearable")

        if f["duty_cycle"] >= 0.60:
            neg.append("very_high_duty_cycle_unusual_for_simple_wearable_advertising")

        return self._candidate("wearable", score, ev, neg)

    def _score_audio_device(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["rf_protocol"] == "ble":
            score += 0.06
            ev.append("protocol=ble")

        if f["duty_cycle"] >= 0.18:
            score += 0.10
            ev.append("moderate_or_higher_duty_cycle")

        if f["stability"] >= 0.55:
            score += 0.10
            ev.append("stable_signal_presence")

        if f["stationary_like"]:
            score += 0.06
            ev.append("stationary_like")

        if mode in {"stationary_interactive", "advertising_general"}:
            score += 0.06
            ev.append(f"mode={mode}")

        if 0.5 <= f["bw"] <= 3.0:
            score += 0.06
            ev.append("bandwidth_ble_like")

        if f["adv_like"]:
            score += 0.06
            ev.append("adv_like")

        if f["mobile_like"]:
            score += 0.04
            ev.append("mobile_association_possible")

        if f["duty_cycle"] <= 0.06:
            neg.append("too_sparse_for_active_audio_accessory_pattern")

        return self._candidate("audio_accessory", score, ev, neg)

    def _score_smart_lock_or_access_control(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["adv_like"]:
            score += 0.16
            ev.append("adv_like")

        if f["stationary_like"]:
            score += 0.18
            ev.append("stationary_like")

        if f["periodic_like"]:
            score += 0.10
            ev.append("periodic_like")

        if f["stability"] >= 0.55:
            score += 0.08
            ev.append("stability>=0.55")

        if f["duty_cycle"] <= 0.25:
            score += 0.06
            ev.append("duty_cycle<=0.25")

        if mode == "advertising_stationary":
            score += 0.10
            ev.append("mode=advertising_stationary")

        if f["mobile_like"]:
            neg.append("mobile_like_conflicts_with_fixed_access_control_device")

        return self._candidate("smart_lock_or_access_control", score, ev, neg)

    def _score_sensor_tag(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["adv_like"]:
            score += 0.18
            ev.append("adv_like")

        if f["periodic_like"]:
            score += 0.12
            ev.append("periodic_like")

        if f["duty_cycle"] <= 0.15:
            score += 0.10
            ev.append("very_low_duty_cycle")

        if f["stationary_like"]:
            score += 0.10
            ev.append("stationary_like")

        if f["temporal_profile"] in {"periodic", "intermittent"}:
            score += 0.06
            ev.append(f"temporal_profile={f['temporal_profile']}")

        if mode == "advertising_stationary":
            score += 0.08
            ev.append("mode=advertising_stationary")

        if f["duty_cycle"] >= 0.45:
            neg.append("high_duty_cycle_conflicts_with_simple_sensor_tag")

        return self._candidate("sensor_tag", score, ev, neg)

    def _score_phone_or_computing_device(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["mobile_like"]:
            score += 0.20
            ev.append("mobile_like")

        if f["duty_cycle"] >= 0.15:
            score += 0.08
            ev.append("moderate_or_higher_duty_cycle")

        if f["stability"] >= 0.30:
            score += 0.05
            ev.append("ongoing_presence")

        if mode in {"mobile_interactive", "advertising_mobile"}:
            score += 0.10
            ev.append(f"mode={mode}")

        if f["adv_like"]:
            score += 0.06
            ev.append("adv_like")

        if f["continuity"] < 0.25:
            score += 0.04
            ev.append("roaming_or_short_presence_possible")

        if f["flood_like"]:
            score -= 0.18
            neg.append("flood_like_conflicts_with_normal_phone_presence")
        if f["linked_signal_count"] >= 8:
            score -= 0.06
            neg.append("too_many_linked_signals_for_normal_phone_presence")

        if f["stationary_like"] and f["mobile_like"] is False:
            neg.append("strong_stationary_pattern_reduces_phone_likelihood")

        return self._candidate("phone_or_computing_device", score, ev, neg)

    def _score_infrastructure_or_gateway(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.0
        ev: List[str] = []
        neg: List[str] = []

        if f["stationary_like"]:
            score += 0.18
            ev.append("stationary_like")

        if f["stability"] >= 0.70:
            score += 0.14
            ev.append("high_stability")

        if f["duty_cycle"] >= 0.20:
            score += 0.06
            ev.append("moderate_duty_cycle")

        if f["observation_count"] >= 6:
            score += 0.06
            ev.append("observation_count>=6")

        if mode == "stationary_interactive":
            score += 0.08
            ev.append("mode=stationary_interactive")

        if f["mobile_like"]:
            neg.append("mobile_like_conflicts_with_infrastructure")

        return self._candidate("infrastructure_gateway", score, ev, neg)

    def _score_unknown_ble_peripheral(self, f: Dict[str, Any], mode: str) -> Dict[str, Any]:
        score = 0.18
        ev: List[str] = ["ble_baseline"]
        neg: List[str] = []

        if f["rf_protocol"] == "ble":
            score += 0.08
            ev.append("protocol=ble")

        if f["adv_like"]:
            score += 0.08
            ev.append("adv_like")

        if mode != "undifferentiated_ble":
            score += 0.04
            ev.append(f"mode={mode}")

        return self._candidate("unknown_ble_peripheral", score, ev, neg)

    # -------------------------------------------------------------------------
    # HEURISTICS
    # -------------------------------------------------------------------------

    def _estimate_adv_like(
        self,
        *,
        ble_dist: Optional[float],
        ble_channel: Optional[int],
        channel_confidence: float,
        bw: float,
        duty_cycle: float,
        burst_periodicity: Optional[float],
        burst_recurrence_score: float,
        temporal_profile: Optional[str],
        signal_class: Optional[str],
        modulation_hint: Optional[str],
        nearest_family: Optional[str],
    ) -> bool:
        score = 0.0

        if ble_channel in {37, 38, 39}:
            score += 0.46

        if ble_dist is not None and ble_dist <= 0.35:
            score += 0.34
        elif ble_dist is not None and ble_dist <= 1.5:
            score += 0.40
        elif ble_dist is not None and ble_dist <= 3.0:
            score += 0.20
        elif ble_dist is not None and ble_dist > 2.0 and ble_channel is None:
            score -= 0.18

        if 0.3 <= bw <= 3.0:
            score += 0.18
        elif bw > 3.5 and ble_channel is None:
            score -= 0.10

        if duty_cycle <= 0.25:
            score += 0.12

        if burst_periodicity is not None and 0.02 <= burst_periodicity <= 2.0:
            score += 0.14

        if burst_recurrence_score >= 0.20:
            score += 0.10

        if temporal_profile in {"periodic", "intermittent", "bursty"}:
            score += 0.08

        if signal_class in {"bursty", "packet_radio", "narrowband"}:
            score += 0.06

        if modulation_hint in {"gfsk_fsk_like", "gfsk", "fsk"}:
            score += 0.08

        if nearest_family == "ble":
            score += 0.08

        if channel_confidence >= 0.8:
            score += 0.08

        return score >= 0.42

    def _estimate_periodic_like(
        self,
        *,
        burst_periodicity: Optional[float],
        temporal_profile: Optional[str],
        duty_cycle: float,
    ) -> bool:
        if burst_periodicity is not None and 0.03 <= burst_periodicity <= 5.0:
            return True
        if temporal_profile == "periodic":
            return True
        if temporal_profile == "intermittent" and duty_cycle <= 0.25:
            return True
        return False

    def _estimate_mobile_like(
        self,
        *,
        continuity: float,
        emitter_state: Optional[str],
        temporal_profile: Optional[str],
        stability: float,
        duty_cycle: float,
    ) -> bool:
        score = 0.0

        if continuity < 0.35:
            score += 0.24
        if stability < 0.45:
            score += 0.18
        if emitter_state in {"candidate", "transient"}:
            score += 0.18
        if temporal_profile in {"bursty", "intermittent"}:
            score += 0.12
        if 0.02 <= duty_cycle <= 0.35:
            score += 0.06

        return score >= 0.36

    def _estimate_stationary_like(
        self,
        *,
        continuity: float,
        emitter_state: Optional[str],
        temporal_profile: Optional[str],
        stability: float,
        duty_cycle: float,
        observation_count: int,
    ) -> bool:
        score = 0.0

        if continuity >= 0.55:
            score += 0.24
        if stability >= 0.55:
            score += 0.22
        if emitter_state in {"stable", "persistent"}:
            score += 0.20
        if temporal_profile in {"periodic", "continuous"}:
            score += 0.08
        if observation_count >= 5:
            score += 0.10
        if duty_cycle <= 0.35:
            score += 0.04

        return score >= 0.40

    def _estimate_dense_cluster_like(
        self,
        *,
        linked_signal_count: int,
        observation_count: int,
        freq_span_mhz: float,
        duty_cycle: float,
    ) -> bool:
        score = 0.0

        if linked_signal_count >= 6:
            score += 0.36
        if observation_count >= 16:
            score += 0.24
        if freq_span_mhz >= 0.8:
            score += 0.24
        if duty_cycle >= 0.30:
            score += 0.16

        return score >= 0.56

    def _estimate_flood_like(
        self,
        *,
        linked_signal_count: int,
        observation_count: int,
        freq_span_mhz: float,
        duty_cycle: float,
        adv_like: bool,
        temporal_profile: Optional[str],
    ) -> bool:
        score = 0.0

        if adv_like:
            score += 0.20
        if linked_signal_count >= 8:
            score += 0.28
        elif linked_signal_count >= 5:
            score += 0.14
        if observation_count >= 20:
            score += 0.20
        elif observation_count >= 12:
            score += 0.10
        if freq_span_mhz >= 1.0:
            score += 0.18
        elif freq_span_mhz >= 0.6:
            score += 0.08
        if duty_cycle >= 0.40:
            score += 0.14
        elif duty_cycle >= 0.25:
            score += 0.08
        if temporal_profile == "continuous":
            score += 0.08

        return score >= 0.58

    # -------------------------------------------------------------------------
    # DECISION SHAPING
    # -------------------------------------------------------------------------

    def _shape_confidence(
        self,
        *,
        best_score: float,
        second_score: float,
        margin: float,
        readiness: float,
        completeness: float,
        stability: float,
        negative_count: int,
        ambiguous: bool,
    ) -> float:
        conf = float(best_score)
        conf += min(margin * 0.35, 0.10)
        conf += min(readiness * 0.14, 0.10)
        conf += min(completeness * 0.10, 0.07)
        conf += min(stability * 0.08, 0.05)
        conf -= min(negative_count * 0.03, 0.09)

        if second_score >= 0.30 and margin < 0.10:
            conf -= 0.06
        if ambiguous:
            conf -= 0.06
        if readiness < 0.30:
            conf -= 0.05
        if completeness < 0.30:
            conf -= 0.04

        return self._clamp(conf, 0.0, 0.95)

    def _decision_state(
        self,
        *,
        best_score: float,
        second_score: float,
        margin: float,
        readiness: float,
        completeness: float,
        stability: float,
        ambiguous: bool,
    ) -> str:
        if readiness < 0.20 or completeness < 0.20:
            return "low_observability"
        if best_score < 0.30:
            return "insufficient_evidence"
        if ambiguous:
            return "contested"
        if best_score >= 0.70 and margin >= 0.18 and readiness >= 0.55:
            return "stable"
        if best_score >= 0.48:
            return "provisional"
        if stability < 0.20 and second_score >= 0.25:
            return "unstable_contested"
        return "weak_positive"

    def _decision_quality(
        self,
        *,
        confidence: float,
        margin: float,
        readiness: float,
        ambiguous: bool,
    ) -> str:
        if confidence >= 0.80 and margin >= 0.18 and readiness >= 0.60 and not ambiguous:
            return "high"
        if confidence >= 0.60 and margin >= 0.10:
            return "medium"
        if confidence >= 0.40:
            return "low"
        return "very_low"

    def _observability_label(
        self,
        *,
        readiness: float,
        completeness: float,
        stability: float,
    ) -> str:
        score = (readiness * 0.45) + (completeness * 0.35) + (stability * 0.20)
        if score >= 0.70:
            return "high"
        if score >= 0.45:
            return "medium"
        if score >= 0.20:
            return "low"
        return "very_low"

    def _candidate_confidence_hint(self, score: float, margin: float) -> float:
        return self._clamp((score * 0.80) + min(margin * 0.20, 0.08), 0.0, 0.95)

    # -------------------------------------------------------------------------
    # OUTPUT HELPERS
    # -------------------------------------------------------------------------

    def _annotate_non_ble(self, emitter: Dict[str, Any], f: Dict[str, Any]) -> Dict[str, Any]:
        emitter["ble_intel_version"] = self.VERSION
        emitter["ble_intelligence_ready"] = False
        emitter["ble_relevant"] = False
        emitter["ble_operating_mode_hint"] = None
        emitter["ble_role"] = None
        emitter["ble_role_confidence"] = 0.0
        emitter["ble_role_secondary"] = None
        emitter["ble_role_secondary_confidence"] = 0.0
        emitter["ble_role_margin"] = 0.0
        emitter["ble_role_ambiguous"] = False
        emitter["ble_decision_state"] = "not_ble_relevant"
        emitter["ble_decision_quality"] = "very_low"
        emitter["ble_evidence"] = []
        emitter["ble_negative_evidence"] = ["not_ble_relevant"]
        emitter["ble_observability"] = self._observability_label(
            readiness=f["readiness"],
            completeness=f["completeness"],
            stability=f["stability"],
        )
        emitter["ble_adv_channel_distance_mhz"] = f["ble_dist"]
        emitter["ble_adv_like"] = False
        emitter["ble_periodic_like"] = False
        emitter["ble_mobile_like"] = False
        emitter["ble_stationary_like"] = False
        emitter["ble_category_candidates"] = []
        return emitter

    def _fallback(self, emitter: Dict[str, Any], reason: str) -> Dict[str, Any]:
        emitter = dict(emitter or {})
        emitter["ble_intel_version"] = self.VERSION
        emitter["ble_intelligence_ready"] = False
        emitter["ble_relevant"] = False
        emitter["ble_operating_mode_hint"] = None
        emitter["ble_role"] = None
        emitter["ble_role_confidence"] = 0.0
        emitter["ble_role_secondary"] = None
        emitter["ble_role_secondary_confidence"] = 0.0
        emitter["ble_role_margin"] = 0.0
        emitter["ble_role_ambiguous"] = False
        emitter["ble_decision_state"] = "error_fallback"
        emitter["ble_decision_quality"] = "very_low"
        emitter["ble_evidence"] = []
        emitter["ble_negative_evidence"] = [reason]
        emitter["ble_observability"] = "very_low"
        emitter["ble_adv_channel_distance_mhz"] = None
        emitter["ble_adv_like"] = False
        emitter["ble_periodic_like"] = False
        emitter["ble_mobile_like"] = False
        emitter["ble_stationary_like"] = False
        emitter["ble_category_candidates"] = []
        return emitter

    def _candidate(
        self,
        role: str,
        score: float,
        evidence: List[str],
        negative_evidence: List[str],
    ) -> Dict[str, Any]:
        return {
            "role": role,
            "score": round(float(score), 4),
            "evidence": list(evidence),
            "negative_evidence": list(negative_evidence),
        }

    def _empty_candidate(self) -> Dict[str, Any]:
        return self._candidate(
            "unknown_ble_peripheral",
            0.0,
            [],
            [],
        )

    def _map_role_to_product_category(self, role: Optional[str]) -> Optional[str]:
        mapping = {
            "ble_advertising_flood": "ble_spam_tool",
            "beacon": "location_beacon",
            "tracker_tag": "asset_tracker",
            "wearable": "wearable",
            "audio_accessory": "audio_device",
            "smart_lock_or_access_control": "smart_lock",
            "sensor_tag": "sensor",
            "phone_or_computing_device": "phone_or_computing",
            "infrastructure_gateway": "gateway_or_hub",
            "unknown_ble_peripheral": None,
        }
        return mapping.get(role)

    def _map_mode_to_behavior_profile(self, mode: Optional[str]) -> Optional[str]:
        mapping = {
            "flooded_advertising": "ble_advertising_flood",
            "advertising_stationary": "stationary_periodic_advertiser",
            "advertising_mobile": "mobile_periodic_advertiser",
            "advertising_general": "general_advertiser",
            "mobile_interactive": "mobile_interactive",
            "stationary_interactive": "stationary_interactive",
            "undifferentiated_ble": "undifferentiated_ble",
        }
        return mapping.get(mode)

    def _map_role_to_rf_device_class(self, role: Optional[str]) -> Optional[str]:
        mapping = {
            "ble_advertising_flood": "ble_flooder",
            "beacon": "ble_beacon",
            "tracker_tag": "ble_tracker",
            "wearable": "ble_wearable",
            "audio_accessory": "ble_accessory",
            "smart_lock_or_access_control": "ble_access_control",
            "sensor_tag": "ble_sensor",
            "phone_or_computing_device": "ble_host_device",
            "infrastructure_gateway": "ble_infrastructure",
            "unknown_ble_peripheral": "ble_unknown",
        }
        return mapping.get(role)

    # -------------------------------------------------------------------------
    # NORMALIZATION HELPERS
    # -------------------------------------------------------------------------

    def _detect_band(self, freq: Optional[float]) -> str:
        if freq is None:
            return "unknown"
        if 2400.0 <= freq <= 2485.0:
            return "2.4ghz"
        if 4900.0 <= freq <= 5900.0:
            return "5ghz"
        if freq < 1000.0:
            return "subghz"
        return "unknown"

    def _signal_span(self, signals: List[Dict[str, Any]]) -> float:
        freqs: List[float] = []
        for signal in signals or []:
            if not isinstance(signal, dict):
                continue
            value = self._f(signal.get("frequency_mhz"), signal.get("freq_mhz"))
            if value is not None:
                freqs.append(value)
        if not freqs:
            return 0.0
        return round(max(freqs) - min(freqs), 4)

    def _norm_band(self, *values: Any) -> str:
        for value in values:
            if value is None:
                continue
            s = str(value).strip().lower()
            if s in {"2.4ghz", "2.4 ghz", "2.4g"}:
                return "2.4ghz"
            if s in {"5ghz", "5 ghz", "5g"}:
                return "5ghz"
            if s in {"subghz", "sub-ghz", "sub ghz"}:
                return "subghz"
            if s:
                return s
        return "unknown"

    def _norm_protocol(self, *values: Any) -> Optional[str]:
        for value in values:
            if value is None:
                continue
            s = str(value).strip().lower()
            mapping = {
                "ble": "ble",
                "bluetooth": "ble",
                "bluetooth_le": "ble",
                "bluetooth_low_energy": "ble",
                "bluetooth low energy": "ble",
                "wifi": "wifi",
                "zigbee": "zigbee",
                "lora": "lora",
                "unknown_rf": "unknown_rf",
            }
            return mapping.get(s, s)
        return None

    def _s(self, *values: Any) -> Optional[str]:
        for value in values:
            if value is None:
                continue
            s = str(value).strip().lower()
            if s:
                return s
        return None

    def _f(self, *values: Any, default: Optional[float] = None) -> Optional[float]:
        for value in values:
            if value is None:
                continue
            try:
                f = float(value)
                if f != f or f == float("inf") or f == float("-inf"):
                    continue
                return f
            except Exception:
                continue
        return default

    def _i(self, *values: Any, default: int = 0) -> int:
        for value in values:
            try:
                return int(value)
            except Exception:
                continue
        return default

    def _clamp(self, value: float, lo: float, hi: float) -> float:
        return max(lo, min(value, hi))
