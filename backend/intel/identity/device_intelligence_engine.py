# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/device_intelligence_engine.py
# VERSION:      v5.1.0 (LIST-AWARE MERGED-DB LOCKED + EXPLAINABLE RANKED IDENTITY)
# LAST UPDATED: 2026-03-15
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
# GhostRecon is an RF red-team intelligence platform built for passive spectrum
# reconnaissance, protocol inference, device fingerprinting, and product/vendor
# attribution across WiFi, BLE, Zigbee, Sub-GHz, and other wireless ecosystems.
#
# This engine is the identity intelligence layer that converts normalized signal
# observations into ranked, explainable device hypotheses using a merged YAML
# intelligence database.
#
# It is designed to support:
# - protocol-aware device class inference
# - vendor and product candidate ranking
# - explainable confidence scoring
# - safe unknown / uncertain fallbacks
# - merged YAML schemas with scalar or list-valued categorical fields
# - red-team surface enrichment
# - future persistence into identity stores and graph intelligence
#
# =============================================================================
# HIGH-LEVEL ARCHITECTURE
# =============================================================================
# Normalized Observation
#        ↓
# Observation Canonicalization
#        ↓
# Intelligence DB Loader (merged YAML)
#        ↓
# Scalar/List-Aware Feature Matching
#        ↓
# Weighted Candidate Scoring
#        ↓
# Device/Product/Vendor Ranking
#        ↓
# Confidence Calibration
#        ↓
# Explainability + Unknown Fallback
#        ↓
# Red-Team Surface Enrichment
#        ↓
# Ranked Identity Result
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
# 1. YAML-LOCKED INTELLIGENCE
#    All matching logic is aligned to a single merged intelligence database.
#
# 2. LIST-AWARE SCHEMA TOLERANCE
#    Profile fields may be declared as scalars or lists. Matching supports both.
#
# 3. EXPLAINABILITY FIRST
#    Every identity result includes score breakdown, reasons, and runner-ups.
#
# 4. SAFE UNCERTAINTY
#    Weak evidence should produce "possible" or "unknown" outputs instead of
#    false precision.
#
# 5. NORMALIZED INPUT CONTRACT
#    Upstream engines should provide normalized fields, but this engine is
#    defensive and performs best-effort canonicalization.
#
# 6. PRODUCTION-ORIENTED
#    Failures degrade gracefully. Missing DB sections do not crash the pipeline.
#
# 7. RED-TEAM RELEVANCE
#    Results are enriched with likely attack surfaces and operational meaning.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
# - Load and validate merged device intelligence YAML
# - Normalize observations
# - Score device, product, and vendor candidates
# - Support scalar and list-based categorical profile fields
# - Return ranked, explainable identity hypotheses
# - Apply uncertainty thresholds and safe fallback naming
# - Attach red-team surfaces and reasoning
#
# =============================================================================
# EXPECTED MERGED YAML SECTIONS
# =============================================================================
# normalization:
# matching_weights:
# confidence_thresholds:
# device_profiles:
# product_profiles:
# burst_signatures:
# redteam_surface_rules:
#
# =============================================================================

from __future__ import annotations

import copy
import logging
import math
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "db",
    "device_intelligence_db.yaml",
)

DEFAULT_MATCHING_WEIGHTS = {
    "protocol_family": 0.18,
    "protocol": 0.08,
    "protocol_subtype": 0.06,
    "device_class": 0.16,
    "vendor": 0.08,
    "product": 0.08,
    "rf_band": 0.06,
    "channel": 0.03,
    "bandwidth_khz": 0.06,
    "modulation": 0.08,
    "burst_interval_ms": 0.05,
    "burst_duration_ms": 0.04,
    "stability": 0.03,
    "shape": 0.03,
    "frame_structure": 0.02,
    "vendor_hint": 0.04,
    "name_hint": 0.02,
}

DEFAULT_CONFIDENCE_THRESHOLDS = {
    "high_confidence": 0.82,
    "medium_confidence": 0.62,
    "low_confidence": 0.42,
    "product_min_confidence": 0.72,
    "vendor_min_confidence": 0.58,
    "unknown_max_confidence": 0.40,
    "min_score_gap_for_precise_label": 0.10,
    "runner_up_close_gap": 0.06,
}

DEFAULT_NORMALIZATION = {
    "protocol_aliases": {},
    "protocol_family_aliases": {},
    "modulation_aliases": {},
    "vendor_aliases": {},
    "device_class_aliases": {},
    "band_aliases": {},
    "field_aliases": {},
}

DEFAULT_REDTTEAM_RULES: List[Dict[str, Any]] = []


@dataclass
class CandidateScore:
    candidate_id: str
    candidate_type: str
    label: str
    score: float
    confidence: float
    reasons: List[str] = field(default_factory=list)
    misses: List[str] = field(default_factory=list)
    matched_features: Dict[str, Any] = field(default_factory=dict)
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DeviceIntelligenceEngine:
    """
    Production-grade explainable identity inference engine.

    Public contract:
        result = engine.identify(observation)

    Recommended normalized observation input:
    {
        "center_freq_mhz": 2440.0,
        "rf_band": "2.4ghz",
        "channel": 20,
        "bandwidth_khz": 2000,
        "modulation": "oqpsk",
        "protocol_family": "zigbee",
        "protocol": "zigbee",
        "protocol_subtype": "door_sensor",
        "device_class": None,
        "vendor_hint": "aqara",
        "name_hint": None,
        "burst_interval_ms": 2500,
        "burst_duration_ms": 8,
        "signal_stability": 0.84,
        "shape_hint": "narrowband_burst",
        "frame_structure": "telemetry_burst",
    }
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db: Dict[str, Any] = {}
        self.normalization: Dict[str, Any] = copy.deepcopy(DEFAULT_NORMALIZATION)
        self.matching_weights: Dict[str, float] = copy.deepcopy(DEFAULT_MATCHING_WEIGHTS)
        self.confidence_thresholds: Dict[str, float] = copy.deepcopy(DEFAULT_CONFIDENCE_THRESHOLDS)

        self.device_profiles: Dict[str, Dict[str, Any]] = {}
        self.product_profiles: Dict[str, Dict[str, Any]] = {}
        self.burst_signatures: Dict[str, Dict[str, Any]] = {}
        self.redteam_surface_rules: List[Dict[str, Any]] = copy.deepcopy(DEFAULT_REDTTEAM_RULES)

        self.reload()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def reload(self) -> None:
        self.db = self._load_yaml(self.db_path)
        self.normalization = self._deep_merge_dicts(
            copy.deepcopy(DEFAULT_NORMALIZATION),
            self.db.get("normalization", {}) or {},
        )
        self.matching_weights = self._deep_merge_dicts(
            copy.deepcopy(DEFAULT_MATCHING_WEIGHTS),
            self.db.get("matching_weights", {}) or {},
        )
        self.confidence_thresholds = self._deep_merge_dicts(
            copy.deepcopy(DEFAULT_CONFIDENCE_THRESHOLDS),
            self.db.get("confidence_thresholds", {}) or {},
        )

        self.device_profiles = self._normalize_profile_map(self.db.get("device_profiles", {}) or {})
        self.product_profiles = self._normalize_profile_map(self.db.get("product_profiles", {}) or {})
        self.burst_signatures = self._normalize_profile_map(self.db.get("burst_signatures", {}) or {})
        self.redteam_surface_rules = self.db.get("redteam_surface_rules", []) or []

        logger.info(
            "DeviceIntelligenceEngine loaded DB: devices=%d products=%d bursts=%d rules=%d path=%s",
            len(self.device_profiles),
            len(self.product_profiles),
            len(self.burst_signatures),
            len(self.redteam_surface_rules),
            self.db_path,
        )

    def identify(self, observation: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
        obs = self._normalize_observation(observation or {})

        device_candidates = self._score_device_profiles(obs)
        product_candidates = self._score_product_profiles(obs, device_candidates)
        vendor_ranking = self._build_vendor_ranking(device_candidates, product_candidates)
        burst_matches = self._score_burst_signatures(obs)

        top_device = device_candidates[0] if device_candidates else None
        top_product = product_candidates[0] if product_candidates else None
        runner_ups = self._collect_runner_ups(device_candidates, product_candidates)
        inferred_surfaces = self._resolve_redteam_surfaces(
            observation=obs,
            top_device=top_device,
            top_product=top_product,
            burst_matches=burst_matches,
        )

        result = self._build_identity_result(
            observation=obs,
            top_device=top_device,
            top_product=top_product,
            vendor_ranking=vendor_ranking,
            burst_matches=burst_matches,
            runner_ups=runner_ups,
            device_candidates=device_candidates[:top_k],
            product_candidates=product_candidates[:top_k],
            redteam_surfaces=inferred_surfaces,
        )

        return result

    def classify(self, observation: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
        return self.identify(observation, top_k=top_k)

    # =========================================================================
    # YAML LOADING
    # =========================================================================

    def _load_yaml(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            logger.warning("Device intelligence DB not found at %s; loading defaults", path)
            return {}

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                logger.warning("Device intelligence DB root is not a dict: %s", path)
                return {}
            return data
        except Exception as exc:
            logger.exception("Failed to load device intelligence DB %s: %s", path, exc)
            return {}

    def _normalize_profile_map(self, value: Any) -> Dict[str, Dict[str, Any]]:
        if isinstance(value, dict):
            out: Dict[str, Dict[str, Any]] = {}
            for k, v in value.items():
                if isinstance(v, dict):
                    out[str(k)] = copy.deepcopy(v)
            return out
        return {}

    # =========================================================================
    # OBSERVATION NORMALIZATION
    # =========================================================================

    def _normalize_observation(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        obs = copy.deepcopy(observation)

        field_aliases = self.normalization.get("field_aliases", {}) or {}
        for src_key, dst_key in field_aliases.items():
            if src_key in obs and dst_key not in obs:
                obs[dst_key] = obs[src_key]

        self._copy_if_present(obs, "freq_mhz", "center_freq_mhz")
        self._copy_if_present(obs, "frequency_mhz", "center_freq_mhz")
        self._copy_if_present(obs, "bandwidth_mhz", "bandwidth_khz", scale=1000.0)
        self._copy_if_present(obs, "avg_stability", "signal_stability")
        self._copy_if_present(obs, "stability", "signal_stability")
        self._copy_if_present(obs, "shape", "shape_hint")

        obs["protocol_family"] = self._best_label_from_value(
            obs.get("protocol_family"),
            self.normalization.get("protocol_family_aliases", {}),
        )
        obs["protocol"] = self._best_label_from_value(
            obs.get("protocol"),
            self.normalization.get("protocol_aliases", {}),
        )
        obs["protocol_subtype"] = self._best_label_from_value(obs.get("protocol_subtype"))
        obs["modulation"] = self._best_label_from_value(
            obs.get("modulation"),
            self.normalization.get("modulation_aliases", {}),
        )
        obs["vendor_hint"] = self._best_label_from_value(
            obs.get("vendor_hint"),
            self.normalization.get("vendor_aliases", {}),
        )
        obs["vendor"] = self._best_label_from_value(
            obs.get("vendor"),
            self.normalization.get("vendor_aliases", {}),
        )
        obs["device_class"] = self._best_label_from_value(
            obs.get("device_class"),
            self.normalization.get("device_class_aliases", {}),
        )
        obs["rf_band"] = self._best_label_from_value(
            obs.get("rf_band"),
            self.normalization.get("band_aliases", {}),
        )
        obs["frame_structure"] = self._best_label_from_value(obs.get("frame_structure"))
        obs["shape_hint"] = self._best_label_from_value(obs.get("shape_hint"))
        obs["name_hint"] = self._best_label_from_value(obs.get("name_hint"))

        obs["center_freq_mhz"] = self._safe_float(obs.get("center_freq_mhz"))
        obs["bandwidth_khz"] = self._safe_float(obs.get("bandwidth_khz"))
        obs["burst_interval_ms"] = self._safe_float(obs.get("burst_interval_ms"))
        obs["burst_duration_ms"] = self._safe_float(obs.get("burst_duration_ms"))
        obs["signal_stability"] = self._clamp(self._safe_float(obs.get("signal_stability")), 0.0, 1.0)
        obs["channel"] = self._safe_int(obs.get("channel"))

        if not obs.get("rf_band"):
            obs["rf_band"] = self._infer_band_from_freq(obs.get("center_freq_mhz"))

        if not obs.get("protocol_family") and obs.get("protocol"):
            obs["protocol_family"] = obs["protocol"]

        return obs

    # =========================================================================
    # PROFILE SCORING
    # =========================================================================

    def _score_device_profiles(self, obs: Dict[str, Any]) -> List[CandidateScore]:
        candidates: List[CandidateScore] = []

        for profile_id, profile in self.device_profiles.items():
            score, reasons, misses, matched, breakdown = self._score_profile(
                obs=obs,
                profile_id=profile_id,
                profile=profile,
                candidate_type="device",
            )

            label = profile.get("label") or profile.get("name") or profile_id
            confidence = self._calibrate_confidence(score, breakdown, reasons, misses)

            candidates.append(
                CandidateScore(
                    candidate_id=profile_id,
                    candidate_type="device",
                    label=label,
                    score=score,
                    confidence=confidence,
                    reasons=reasons,
                    misses=misses,
                    matched_features=matched,
                    score_breakdown=breakdown,
                    metadata={
                        "vendor": self._best_label_from_value(
                            profile.get("vendor"),
                            self.normalization.get("vendor_aliases", {}),
                        ),
                        "device_class": self._best_label_from_value(
                            profile.get("device_class") or profile.get("class"),
                            self.normalization.get("device_class_aliases", {}),
                        ),
                        "protocol_family": self._best_label_from_value(
                            profile.get("protocol_family"),
                            self.normalization.get("protocol_family_aliases", {}),
                        ),
                        "raw_profile": profile,
                    },
                )
            )

        candidates.sort(key=lambda x: (x.score, x.confidence), reverse=True)
        return candidates

    def _score_product_profiles(
        self,
        obs: Dict[str, Any],
        device_candidates: List[CandidateScore],
    ) -> List[CandidateScore]:
        candidates: List[CandidateScore] = []

        top_device = device_candidates[0] if device_candidates else None
        top_device_class = None
        top_device_vendor = None
        top_device_protocol_family = None

        if top_device:
            top_device_class = top_device.metadata.get("device_class")
            top_device_vendor = top_device.metadata.get("vendor")
            top_device_protocol_family = top_device.metadata.get("protocol_family")

        for profile_id, profile in self.product_profiles.items():
            score, reasons, misses, matched, breakdown = self._score_profile(
                obs=obs,
                profile_id=profile_id,
                profile=profile,
                candidate_type="product",
            )

            align_bonus = 0.0
            product_vendor = self._best_label_from_value(
                profile.get("vendor"),
                self.normalization.get("vendor_aliases", {}),
            )
            product_device_class = self._best_label_from_value(
                profile.get("device_class") or profile.get("class"),
                self.normalization.get("device_class_aliases", {}),
            )
            product_protocol_family = self._best_label_from_value(
                profile.get("protocol_family"),
                self.normalization.get("protocol_family_aliases", {}),
            )

            if top_device_class and product_device_class and product_device_class == top_device_class:
                align_bonus += 0.04
                breakdown["device_alignment"] = breakdown.get("device_alignment", 0.0) + 0.04
                reasons.append(f"Aligned with top device class '{top_device_class}'")

            if top_device_vendor and product_vendor and product_vendor == top_device_vendor:
                align_bonus += 0.03
                breakdown["vendor_alignment"] = breakdown.get("vendor_alignment", 0.0) + 0.03
                reasons.append(f"Aligned with top device vendor '{top_device_vendor}'")

            if (
                top_device_protocol_family
                and product_protocol_family
                and product_protocol_family == top_device_protocol_family
            ):
                align_bonus += 0.02
                breakdown["protocol_alignment"] = breakdown.get("protocol_alignment", 0.0) + 0.02
                reasons.append(
                    f"Aligned with top device protocol family '{top_device_protocol_family}'"
                )

            score = min(1.0, score + align_bonus)
            confidence = self._calibrate_confidence(score, breakdown, reasons, misses)

            label = profile.get("label") or profile.get("name") or profile_id

            candidates.append(
                CandidateScore(
                    candidate_id=profile_id,
                    candidate_type="product",
                    label=label,
                    score=score,
                    confidence=confidence,
                    reasons=reasons,
                    misses=misses,
                    matched_features=matched,
                    score_breakdown=breakdown,
                    metadata={
                        "vendor": product_vendor,
                        "device_class": product_device_class,
                        "protocol_family": product_protocol_family,
                        "raw_profile": profile,
                    },
                )
            )

        candidates.sort(key=lambda x: (x.score, x.confidence), reverse=True)
        return candidates

    def _score_burst_signatures(self, obs: Dict[str, Any]) -> List[CandidateScore]:
        candidates: List[CandidateScore] = []

        for sig_id, sig in self.burst_signatures.items():
            score = 0.0
            reasons: List[str] = []
            misses: List[str] = []
            matched: Dict[str, Any] = {}
            breakdown: Dict[str, float] = {}

            expected_interval = self._extract_range(sig, ["burst_interval_ms", "interval_ms"])
            expected_duration = self._extract_range(sig, ["burst_duration_ms", "duration_ms"])
            expected_modulation = self._normalize_value_set(
                sig.get("modulation"),
                self.normalization.get("modulation_aliases", {}),
            )
            expected_shape = self._normalize_value_set(sig.get("shape_hint") or sig.get("shape"))
            expected_frame = self._normalize_value_set(sig.get("frame_structure"))

            if expected_interval and obs.get("burst_interval_ms") is not None:
                s = self._score_range(obs["burst_interval_ms"], expected_interval)
                score += s * 0.45
                breakdown["burst_interval_ms"] = s * 0.45
                if s > 0:
                    matched["burst_interval_ms"] = obs["burst_interval_ms"]
                    reasons.append("Burst interval aligned with known burst signature")
                else:
                    misses.append("Burst interval did not align with burst signature")

            if expected_duration and obs.get("burst_duration_ms") is not None:
                s = self._score_range(obs["burst_duration_ms"], expected_duration)
                score += s * 0.25
                breakdown["burst_duration_ms"] = s * 0.25
                if s > 0:
                    matched["burst_duration_ms"] = obs["burst_duration_ms"]
                    reasons.append("Burst duration aligned with known burst signature")
                else:
                    misses.append("Burst duration did not align with burst signature")

            if expected_modulation:
                s = self._score_token_set(
                    obs.get("modulation"),
                    expected_modulation,
                    self.normalization.get("modulation_aliases", {}),
                )
                score += s * 0.15
                breakdown["modulation"] = s * 0.15
                if s > 0:
                    matched["modulation"] = obs.get("modulation")
                    reasons.append(f"Modulation matched burst signature from {expected_modulation}")

            if expected_shape:
                s = self._score_token_set(obs.get("shape_hint"), expected_shape)
                score += s * 0.10
                breakdown["shape_hint"] = s * 0.10
                if s > 0:
                    matched["shape_hint"] = obs.get("shape_hint")
                    reasons.append(f"Shape matched burst signature from {expected_shape}")

            if expected_frame:
                s = self._score_token_set(obs.get("frame_structure"), expected_frame)
                score += s * 0.05
                breakdown["frame_structure"] = s * 0.05
                if s > 0:
                    matched["frame_structure"] = obs.get("frame_structure")
                    reasons.append(f"Frame structure matched burst signature from {expected_frame}")

            if score <= 0:
                continue

            candidates.append(
                CandidateScore(
                    candidate_id=sig_id,
                    candidate_type="burst_signature",
                    label=sig.get("label") or sig.get("name") or sig_id,
                    score=min(1.0, score),
                    confidence=min(1.0, score),
                    reasons=reasons,
                    misses=misses,
                    matched_features=matched,
                    score_breakdown=breakdown,
                    metadata={"raw_profile": sig},
                )
            )

        candidates.sort(key=lambda x: (x.score, x.confidence), reverse=True)
        return candidates

    def _score_profile(
        self,
        obs: Dict[str, Any],
        profile_id: str,
        profile: Dict[str, Any],
        candidate_type: str,
    ) -> Tuple[float, List[str], List[str], Dict[str, Any], Dict[str, float]]:
        reasons: List[str] = []
        misses: List[str] = []
        matched: Dict[str, Any] = {}
        breakdown: Dict[str, float] = {}

        total_score = 0.0

        def add(feature: str, raw_score: float, reason: Optional[str] = None, miss: Optional[str] = None) -> None:
            nonlocal total_score
            weighted = raw_score * self.matching_weights.get(feature, 0.0)
            if weighted > 0:
                breakdown[feature] = breakdown.get(feature, 0.0) + weighted
                total_score += weighted
                if reason:
                    reasons.append(reason)
            else:
                if miss:
                    misses.append(miss)

        expected_protocol_family = self._normalize_value_set(
            profile.get("protocol_family"),
            self.normalization.get("protocol_family_aliases", {}),
        )
        if expected_protocol_family:
            s = self._score_token_set(
                obs.get("protocol_family"),
                expected_protocol_family,
                self.normalization.get("protocol_family_aliases", {}),
            )
            if s > 0:
                matched["protocol_family"] = obs.get("protocol_family")
            add(
                "protocol_family",
                s,
                reason=f"Matched protocol family from {expected_protocol_family}" if s > 0 else None,
                miss=f"Expected protocol family in {expected_protocol_family}",
            )

        expected_protocol = self._normalize_value_set(
            profile.get("protocol"),
            self.normalization.get("protocol_aliases", {}),
        )
        if expected_protocol:
            s = self._score_token_set(
                obs.get("protocol"),
                expected_protocol,
                self.normalization.get("protocol_aliases", {}),
            )
            if s > 0:
                matched["protocol"] = obs.get("protocol")
            add(
                "protocol",
                s,
                reason=f"Matched protocol from {expected_protocol}" if s > 0 else None,
                miss=f"Expected protocol in {expected_protocol}",
            )

        expected_subtype = self._normalize_value_set(profile.get("protocol_subtype"))
        if expected_subtype:
            s = self._score_token_set(obs.get("protocol_subtype"), expected_subtype)
            if s > 0:
                matched["protocol_subtype"] = obs.get("protocol_subtype")
            add(
                "protocol_subtype",
                s,
                reason=f"Matched protocol subtype from {expected_subtype}" if s > 0 else None,
                miss=f"Expected subtype in {expected_subtype}",
            )

        expected_device_class = self._normalize_value_set(
            profile.get("device_class") or profile.get("class"),
            self.normalization.get("device_class_aliases", {}),
        )
        if expected_device_class:
            s = self._score_token_set(
                obs.get("device_class"),
                expected_device_class,
                self.normalization.get("device_class_aliases", {}),
            )
            if s == 0 and obs.get("name_hint"):
                name_hint = obs.get("name_hint", "")
                for dc in expected_device_class:
                    if dc in name_hint:
                        s = 0.6
                        break
            if s > 0:
                matched["device_class"] = expected_device_class[0]
            add(
                "device_class",
                s,
                reason=f"Matched device class from {expected_device_class}" if s > 0 else None,
                miss=f"Expected device class in {expected_device_class}",
            )

        expected_vendor = self._normalize_value_set(
            profile.get("vendor"),
            self.normalization.get("vendor_aliases", {}),
        )
        if expected_vendor:
            vendor_obs = obs.get("vendor") or obs.get("vendor_hint")
            s = self._score_token_set(
                vendor_obs,
                expected_vendor,
                self.normalization.get("vendor_aliases", {}),
            )
            if s > 0:
                matched["vendor"] = vendor_obs
            add(
                "vendor",
                s,
                reason=f"Matched vendor from {expected_vendor}" if s > 0 else None,
                miss=f"Expected vendor in {expected_vendor}",
            )

        expected_product = self._best_label_from_value(profile.get("product") or profile.get("name"))
        if expected_product and candidate_type == "product":
            s = self._score_soft_text(obs.get("name_hint"), expected_product)
            if s > 0:
                matched["product"] = obs.get("name_hint")
            add(
                "product",
                s,
                reason=f"Name hint aligned with product '{expected_product}'" if s > 0 else None,
                miss=f"Expected product/name pattern for '{expected_product}'",
            )

        expected_band = self._normalize_value_set(
            profile.get("rf_band"),
            self.normalization.get("band_aliases", {}),
        )
        if expected_band:
            s = self._score_token_set(
                obs.get("rf_band"),
                expected_band,
                self.normalization.get("band_aliases", {}),
            )
            if s > 0:
                matched["rf_band"] = obs.get("rf_band")
            add(
                "rf_band",
                s,
                reason=f"Matched RF band from {expected_band}" if s > 0 else None,
                miss=f"Expected RF band in {expected_band}",
            )

        expected_channel = profile.get("channel")
        if expected_channel is not None and obs.get("channel") is not None:
            s = self._score_channel(obs.get("channel"), expected_channel)
            if s > 0:
                matched["channel"] = obs.get("channel")
            add(
                "channel",
                s,
                reason=f"Channel aligned with expected profile '{expected_channel}'" if s > 0 else None,
                miss=f"Expected channel '{expected_channel}'",
            )

        expected_bw = self._extract_range(profile, ["bandwidth_khz", "bandwidth"])
        if expected_bw and obs.get("bandwidth_khz") is not None:
            s = self._score_range(obs.get("bandwidth_khz"), expected_bw)
            if s > 0:
                matched["bandwidth_khz"] = obs.get("bandwidth_khz")
            add(
                "bandwidth_khz",
                s,
                reason="Bandwidth aligned with expected range" if s > 0 else None,
                miss="Bandwidth outside expected range",
            )

        expected_mod = self._normalize_value_set(
            profile.get("modulation"),
            self.normalization.get("modulation_aliases", {}),
        )
        if expected_mod:
            s = self._score_token_set(
                obs.get("modulation"),
                expected_mod,
                self.normalization.get("modulation_aliases", {}),
            )
            if s > 0:
                matched["modulation"] = obs.get("modulation")
            add(
                "modulation",
                s,
                reason=f"Matched modulation from {expected_mod}" if s > 0 else None,
                miss=f"Expected modulation in {expected_mod}",
            )

        expected_interval = self._extract_range(profile, ["burst_interval_ms", "interval_ms"])
        if expected_interval and obs.get("burst_interval_ms") is not None:
            s = self._score_range(obs.get("burst_interval_ms"), expected_interval)
            if s > 0:
                matched["burst_interval_ms"] = obs.get("burst_interval_ms")
            add(
                "burst_interval_ms",
                s,
                reason="Burst interval aligned with expected range" if s > 0 else None,
                miss="Burst interval outside expected range",
            )

        expected_duration = self._extract_range(profile, ["burst_duration_ms", "duration_ms"])
        if expected_duration and obs.get("burst_duration_ms") is not None:
            s = self._score_range(obs.get("burst_duration_ms"), expected_duration)
            if s > 0:
                matched["burst_duration_ms"] = obs.get("burst_duration_ms")
            add(
                "burst_duration_ms",
                s,
                reason="Burst duration aligned with expected range" if s > 0 else None,
                miss="Burst duration outside expected range",
            )

        expected_stability = self._extract_range(profile, ["signal_stability", "stability"])
        if expected_stability and obs.get("signal_stability") is not None:
            s = self._score_range(obs.get("signal_stability"), expected_stability)
            if s > 0:
                matched["signal_stability"] = obs.get("signal_stability")
            add(
                "stability",
                s,
                reason="Signal stability aligned with expected range" if s > 0 else None,
                miss="Signal stability outside expected range",
            )

        expected_shape = self._normalize_value_set(profile.get("shape_hint") or profile.get("shape"))
        if expected_shape:
            s = self._score_token_set(obs.get("shape_hint"), expected_shape)
            if s > 0:
                matched["shape_hint"] = obs.get("shape_hint")
            add(
                "shape",
                s,
                reason=f"Matched spectral/envelope shape from {expected_shape}" if s > 0 else None,
                miss=f"Expected shape in {expected_shape}",
            )

        expected_frame = self._normalize_value_set(profile.get("frame_structure"))
        if expected_frame:
            s = self._score_token_set(obs.get("frame_structure"), expected_frame)
            if s > 0:
                matched["frame_structure"] = obs.get("frame_structure")
            add(
                "frame_structure",
                s,
                reason=f"Matched frame structure from {expected_frame}" if s > 0 else None,
                miss=f"Expected frame structure in {expected_frame}",
            )

        if expected_vendor and obs.get("vendor_hint"):
            s = self._score_token_set(
                obs.get("vendor_hint"),
                expected_vendor,
                self.normalization.get("vendor_aliases", {}),
            )
            if s > 0:
                matched["vendor_hint"] = obs.get("vendor_hint")
            add(
                "vendor_hint",
                s,
                reason=f"Vendor hint aligned with {expected_vendor}" if s > 0 else None,
                miss=f"Vendor hint did not align with {expected_vendor}",
            )

        if obs.get("name_hint"):
            textual_label = self._best_label_from_value(profile.get("label") or profile.get("name") or profile_id)
            s = self._score_soft_text(obs.get("name_hint"), textual_label)
            if s > 0:
                matched["name_hint"] = obs.get("name_hint")
            add(
                "name_hint",
                s,
                reason=f"Name hint aligned with '{textual_label}'" if s > 0 else None,
                miss=f"Name hint did not align with '{textual_label}'",
            )

        return min(1.0, total_score), reasons, misses, matched, breakdown

    # =========================================================================
    # RESULT BUILDING
    # =========================================================================

    def _build_identity_result(
        self,
        observation: Dict[str, Any],
        top_device: Optional[CandidateScore],
        top_product: Optional[CandidateScore],
        vendor_ranking: List[Dict[str, Any]],
        burst_matches: List[CandidateScore],
        runner_ups: List[Dict[str, Any]],
        device_candidates: List[CandidateScore],
        product_candidates: List[CandidateScore],
        redteam_surfaces: List[str],
    ) -> Dict[str, Any]:
        thresholds = self.confidence_thresholds

        top_vendor = vendor_ranking[0]["vendor"] if vendor_ranking else None
        top_vendor_conf = vendor_ranking[0]["confidence"] if vendor_ranking else 0.0

        device_conf = top_device.confidence if top_device else 0.0
        product_conf = top_product.confidence if top_product else 0.0

        device_gap = self._gap(
            device_candidates[0].score if len(device_candidates) > 0 else 0.0,
            device_candidates[1].score if len(device_candidates) > 1 else 0.0,
        )
        product_gap = self._gap(
            product_candidates[0].score if len(product_candidates) > 0 else 0.0,
            product_candidates[1].score if len(product_candidates) > 1 else 0.0,
        )

        precise_device_allowed = (
            top_device is not None
            and device_conf >= thresholds["medium_confidence"]
            and device_gap >= thresholds["min_score_gap_for_precise_label"]
        )

        precise_product_allowed = (
            top_product is not None
            and product_conf >= thresholds["product_min_confidence"]
            and product_gap >= thresholds["min_score_gap_for_precise_label"]
        )

        protocol_family = (
            top_device.metadata.get("protocol_family")
            if top_device and top_device.metadata.get("protocol_family")
            else observation.get("protocol_family") or "unknown"
        )

        device_class = (
            top_device.metadata.get("device_class")
            if top_device and top_device.metadata.get("device_class")
            else None
        )

        vendor = top_vendor if top_vendor_conf >= thresholds["vendor_min_confidence"] else None

        if precise_product_allowed:
            device_name = top_product.label
            certainty = "precise"
        elif precise_device_allowed and top_device:
            device_name = top_device.label
            certainty = "probable"
        else:
            device_name = self._build_unknown_label(observation, top_device)
            certainty = "uncertain"

        reasons = []
        misses = []
        score_breakdown = {}

        if top_product:
            reasons.extend(top_product.reasons[:6])
            misses.extend(top_product.misses[:4])
            score_breakdown.update(top_product.score_breakdown)

        if top_device:
            for r in top_device.reasons:
                if r not in reasons:
                    reasons.append(r)
            for m in top_device.misses:
                if m not in misses:
                    misses.append(m)
            for k, v in top_device.score_breakdown.items():
                score_breakdown[k] = max(score_breakdown.get(k, 0.0), v)

        confidence = max(device_conf, product_conf * 0.98)

        result = {
            "version": "v5.1.0",
            "engine": "DeviceIntelligenceEngine",
            "db_path": self.db_path,
            "identity_status": certainty,
            "confidence": round(confidence, 4),
            "device_confidence": round(device_conf, 4),
            "product_confidence": round(product_conf, 4),
            "vendor_confidence": round(top_vendor_conf, 4),
            "protocol_family": protocol_family,
            "protocol": observation.get("protocol"),
            "protocol_subtype": observation.get("protocol_subtype"),
            "device": device_name,
            "device_class": device_class,
            "vendor": vendor,
            "product_candidate": top_product.label if top_product else None,
            "product_id": top_product.candidate_id if top_product else None,
            "device_candidate": top_device.label if top_device else None,
            "device_id": top_device.candidate_id if top_device else None,
            "rf_band": observation.get("rf_band"),
            "channel": observation.get("channel"),
            "center_freq_mhz": observation.get("center_freq_mhz"),
            "bandwidth_khz": observation.get("bandwidth_khz"),
            "modulation": observation.get("modulation"),
            "burst_interval_ms": observation.get("burst_interval_ms"),
            "burst_duration_ms": observation.get("burst_duration_ms"),
            "signal_stability": observation.get("signal_stability"),
            "redteam_surfaces": redteam_surfaces,
            "explanation": reasons[:10],
            "misses": misses[:8],
            "score_breakdown": self._round_dict(score_breakdown),
            "runner_ups": runner_ups[:5],
            "top_burst_signatures": [
                {
                    "label": c.label,
                    "score": round(c.score, 4),
                    "confidence": round(c.confidence, 4),
                }
                for c in burst_matches[:3]
            ],
            "ranked_candidates": {
                "devices": [self._candidate_to_dict(c) for c in device_candidates[:5]],
                "products": [self._candidate_to_dict(c) for c in product_candidates[:5]],
                "vendors": vendor_ranking[:5],
            },
            "unknown_reason": None if certainty != "uncertain" else self._build_unknown_reason(
                observation, device_candidates, product_candidates
            ),
            "observation_normalized": observation,
        }

        return result

    def _build_vendor_ranking(
        self,
        device_candidates: List[CandidateScore],
        product_candidates: List[CandidateScore],
    ) -> List[Dict[str, Any]]:
        vendor_scores: Dict[str, float] = {}

        for candidate in device_candidates[:5]:
            vendor = candidate.metadata.get("vendor")
            if vendor:
                vendor_scores[vendor] = vendor_scores.get(vendor, 0.0) + candidate.score * 0.75

        for candidate in product_candidates[:5]:
            vendor = candidate.metadata.get("vendor")
            if vendor:
                vendor_scores[vendor] = vendor_scores.get(vendor, 0.0) + candidate.score * 1.00

        ranking = [
            {"vendor": vendor, "confidence": round(min(1.0, score), 4)}
            for vendor, score in sorted(vendor_scores.items(), key=lambda x: x[1], reverse=True)
        ]
        return ranking

    def _collect_runner_ups(
        self,
        device_candidates: List[CandidateScore],
        product_candidates: List[CandidateScore],
    ) -> List[Dict[str, Any]]:
        runner_ups: List[Dict[str, Any]] = []
        close_gap = self.confidence_thresholds["runner_up_close_gap"]

        if len(device_candidates) > 1:
            top = device_candidates[0].score
            for c in device_candidates[1:3]:
                if (top - c.score) <= close_gap:
                    runner_ups.append(
                        {
                            "type": "device",
                            "label": c.label,
                            "score": round(c.score, 4),
                            "confidence": round(c.confidence, 4),
                        }
                    )

        if len(product_candidates) > 1:
            top = product_candidates[0].score
            for c in product_candidates[1:3]:
                if (top - c.score) <= close_gap:
                    runner_ups.append(
                        {
                            "type": "product",
                            "label": c.label,
                            "score": round(c.score, 4),
                            "confidence": round(c.confidence, 4),
                        }
                    )

        return runner_ups

    def _resolve_redteam_surfaces(
        self,
        observation: Dict[str, Any],
        top_device: Optional[CandidateScore],
        top_product: Optional[CandidateScore],
        burst_matches: List[CandidateScore],
    ) -> List[str]:
        surfaces = set()

        raw_profiles = []
        if top_device:
            raw_profiles.append(top_device.metadata.get("raw_profile", {}))
        if top_product:
            raw_profiles.append(top_product.metadata.get("raw_profile", {}))
        if burst_matches:
            raw_profiles.extend([b.metadata.get("raw_profile", {}) for b in burst_matches[:2]])

        for profile in raw_profiles:
            for key in ("redteam_surfaces", "attack_surfaces", "surfaces"):
                values = profile.get(key)
                if isinstance(values, list):
                    for v in values:
                        if v:
                            surfaces.add(str(v))

        for rule in self.redteam_surface_rules:
            if self._rule_matches(rule, observation, top_device, top_product):
                for s in rule.get("surfaces", []) or []:
                    surfaces.add(str(s))

        return sorted(surfaces)

    def _rule_matches(
        self,
        rule: Dict[str, Any],
        observation: Dict[str, Any],
        top_device: Optional[CandidateScore],
        top_product: Optional[CandidateScore],
    ) -> bool:
        expected_pf = self._best_label_from_value(rule.get("protocol_family"))
        expected_vendor = self._best_label_from_value(rule.get("vendor"))
        expected_device_class = self._best_label_from_value(rule.get("device_class"))

        actual_pf = (
            top_device.metadata.get("protocol_family") if top_device else observation.get("protocol_family")
        )
        actual_vendor = (
            top_product.metadata.get("vendor")
            if top_product and top_product.metadata.get("vendor")
            else (top_device.metadata.get("vendor") if top_device else observation.get("vendor_hint"))
        )
        actual_device_class = (
            top_product.metadata.get("device_class")
            if top_product and top_product.metadata.get("device_class")
            else (top_device.metadata.get("device_class") if top_device else observation.get("device_class"))
        )

        if expected_pf and actual_pf != expected_pf:
            return False
        if expected_vendor and actual_vendor != expected_vendor:
            return False
        if expected_device_class and actual_device_class != expected_device_class:
            return False

        return True

    # =========================================================================
    # MATCHING HELPERS
    # =========================================================================

    def _normalize_value_set(self, value: Any, aliases: Optional[Dict[str, Any]] = None) -> List[str]:
        if value is None:
            return []

        items: List[Any]
        if isinstance(value, list):
            items = value
        else:
            items = [value]

        out: List[str] = []
        for item in items:
            norm = self._norm_token(item, aliases)
            if norm:
                out.append(norm)

        seen = set()
        deduped = []
        for item in out:
            if item not in seen:
                seen.add(item)
                deduped.append(item)

        return deduped

    def _score_token_set(self, actual: Any, expected: Any, aliases: Optional[Dict[str, Any]] = None) -> float:
        actual_set = set(self._normalize_value_set(actual, aliases))
        expected_set = set(self._normalize_value_set(expected, aliases))

        if not actual_set or not expected_set:
            return 0.0

        if actual_set & expected_set:
            return 1.0

        return 0.0

    def _best_label_from_value(self, value: Any, aliases: Optional[Dict[str, Any]] = None) -> Optional[str]:
        values = self._normalize_value_set(value, aliases)
        return values[0] if values else None

    def _score_soft_text(self, actual: Optional[str], expected: Optional[str]) -> float:
        if not actual or not expected:
            return 0.0
        a = self._norm_token(actual)
        e = self._norm_token(expected)
        if not a or not e:
            return 0.0
        if a == e:
            return 1.0
        if e in a or a in e:
            return 0.75
        aset = set(a.split("_"))
        eset = set(e.split("_"))
        if not aset or not eset:
            return 0.0
        overlap = len(aset & eset) / max(len(eset), 1)
        return round(min(0.7, overlap), 4)

    def _score_channel(self, actual: int, expected: Any) -> float:
        if actual is None or expected is None:
            return 0.0
        if isinstance(expected, list):
            try:
                expected_vals = [int(x) for x in expected]
                return 1.0 if actual in expected_vals else 0.0
            except Exception:
                return 0.0
        try:
            return 1.0 if int(actual) == int(expected) else 0.0
        except Exception:
            return 0.0

    def _score_range(self, value: float, expected_range: Dict[str, float]) -> float:
        if value is None or not expected_range:
            return 0.0

        lo = expected_range.get("min")
        hi = expected_range.get("max")
        tol = expected_range.get("tolerance", 0.0)

        if lo is None and hi is None:
            exact = expected_range.get("value")
            if exact is not None:
                diff = abs(value - exact)
                if tol and diff <= tol:
                    return max(0.0, 1.0 - (diff / max(tol, 1e-6)))
                return 1.0 if diff == 0 else 0.0
            return 0.0

        lo_eff = lo - tol if lo is not None else None
        hi_eff = hi + tol if hi is not None else None

        if lo_eff is not None and value < lo_eff:
            return 0.0
        if hi_eff is not None and value > hi_eff:
            return 0.0

        if lo is not None and hi is not None and hi > lo:
            center = (lo + hi) / 2.0
            half_span = max((hi - lo) / 2.0 + tol, 1e-6)
            dist = abs(value - center)
            return max(0.0, 1.0 - (dist / half_span) * 0.35)

        return 1.0

    def _calibrate_confidence(
        self,
        score: float,
        breakdown: Dict[str, float],
        reasons: List[str],
        misses: List[str],
    ) -> float:
        evidence_bonus = min(0.12, len(reasons) * 0.015)
        penalty = min(0.10, len(misses) * 0.01)
        diversity_bonus = min(0.08, len([k for k, v in breakdown.items() if v > 0]) * 0.01)
        conf = score + evidence_bonus + diversity_bonus - penalty
        return round(self._clamp(conf, 0.0, 1.0), 4)

    # =========================================================================
    # UNKNOWN / FALLBACK
    # =========================================================================

    def _build_unknown_label(
        self,
        observation: Dict[str, Any],
        top_device: Optional[CandidateScore],
    ) -> str:
        protocol_family = observation.get("protocol_family")
        if top_device and top_device.metadata.get("device_class"):
            dc = top_device.metadata["device_class"].replace("_", " ").title()
            return f"Possible {dc}"
        if protocol_family and protocol_family != "unknown":
            return f"Unknown {str(protocol_family).upper()} Device"
        band = observation.get("rf_band")
        if band:
            return f"Unknown {band} RF Device"
        return "Unknown RF Device"

    def _build_unknown_reason(
        self,
        observation: Dict[str, Any],
        device_candidates: List[CandidateScore],
        product_candidates: List[CandidateScore],
    ) -> str:
        if not device_candidates and not product_candidates:
            return "No matching device or product profiles produced a meaningful score."

        reasons = []
        if device_candidates:
            top = device_candidates[0]
            reasons.append(
                f"Top device score {top.score:.2f} / confidence {top.confidence:.2f} remained below precise identification threshold."
            )
            if len(device_candidates) > 1:
                gap = top.score - device_candidates[1].score
                reasons.append(f"Device score gap to runner-up was only {gap:.2f}.")

        if product_candidates:
            top = product_candidates[0]
            reasons.append(
                f"Top product score {top.score:.2f} / confidence {top.confidence:.2f} was insufficient for product-level attribution."
            )

        if not observation.get("vendor_hint"):
            reasons.append("No reliable vendor hint was present.")
        if not observation.get("name_hint"):
            reasons.append("No product/name hint was present.")
        if not observation.get("burst_interval_ms"):
            reasons.append("Burst timing evidence was limited or absent.")

        return " ".join(reasons)

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def _candidate_to_dict(self, c: CandidateScore) -> Dict[str, Any]:
        return {
            "id": c.candidate_id,
            "type": c.candidate_type,
            "label": c.label,
            "score": round(c.score, 4),
            "confidence": round(c.confidence, 4),
            "score_breakdown": self._round_dict(c.score_breakdown),
            "reasons": c.reasons[:6],
            "misses": c.misses[:4],
            "matched_features": c.matched_features,
            "vendor": c.metadata.get("vendor"),
            "device_class": c.metadata.get("device_class"),
            "protocol_family": c.metadata.get("protocol_family"),
        }

    def _extract_range(self, profile: Dict[str, Any], keys: List[str]) -> Optional[Dict[str, float]]:
        for key in keys:
            if key not in profile:
                continue
            value = profile.get(key)

            if isinstance(value, dict):
                out: Dict[str, float] = {}
                for k in ("min", "max", "value", "tolerance"):
                    if k in value and value[k] is not None:
                        out[k] = float(value[k])
                if out:
                    return out

            if isinstance(value, (int, float)):
                return {"value": float(value), "tolerance": 0.0}

            if isinstance(value, list) and len(value) == 2:
                try:
                    return {"min": float(value[0]), "max": float(value[1]), "tolerance": 0.0}
                except Exception:
                    continue

        return None

    def _infer_band_from_freq(self, center_freq_mhz: Optional[float]) -> Optional[str]:
        if center_freq_mhz is None:
            return None
        f = center_freq_mhz
        if 2400 <= f <= 2500:
            return "2.4ghz"
        if 5000 <= f <= 5900:
            return "5ghz"
        if 860 <= f <= 930:
            return "subghz_900"
        if 430 <= f <= 450:
            return "subghz_433"
        return None

    def _norm_token(self, value: Any, aliases: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if value is None:
            return None
        s = str(value).strip().lower()
        if not s:
            return None

        s = (
            s.replace("/", "_")
            .replace("-", "_")
            .replace(" ", "_")
            .replace("__", "_")
        )

        aliases = aliases or {}
        if s in aliases:
            mapped = aliases[s]
            if isinstance(mapped, list):
                if not mapped:
                    return None
                return self._norm_token(mapped[0], aliases=None)
            return self._norm_token(mapped, aliases=None)

        return s

    def _copy_if_present(
        self,
        d: Dict[str, Any],
        src: str,
        dst: str,
        scale: Optional[float] = None,
    ) -> None:
        if src in d and dst not in d:
            value = d[src]
            if scale is not None and value is not None:
                try:
                    value = float(value) * scale
                except Exception:
                    pass
            d[dst] = value

    def _safe_float(self, value: Any) -> Optional[float]:
        if value is None or value == "":
            return None
        try:
            if isinstance(value, bool):
                return None
            if isinstance(value, (int, float)):
                if math.isnan(float(value)) or math.isinf(float(value)):
                    return None
                return float(value)
            return float(str(value).strip())
        except Exception:
            return None

    def _safe_int(self, value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        try:
            if isinstance(value, bool):
                return None
            return int(float(value))
        except Exception:
            return None

    def _clamp(self, value: Optional[float], lo: float, hi: float) -> Optional[float]:
        if value is None:
            return None
        return max(lo, min(hi, value))

    def _deep_merge_dicts(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = copy.deepcopy(base)
        for k, v in (override or {}).items():
            if isinstance(v, dict) and isinstance(result.get(k), dict):
                result[k] = self._deep_merge_dicts(result[k], v)
            else:
                result[k] = copy.deepcopy(v)
        return result

    def _round_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        for k, v in d.items():
            if isinstance(v, float):
                out[k] = round(v, 4)
            else:
                out[k] = v
        return out

    def _gap(self, a: float, b: float) -> float:
        return max(0.0, a - b)


_ENGINE: Optional[DeviceIntelligenceEngine] = None


def get_device_intelligence_engine(db_path: Optional[str] = None) -> DeviceIntelligenceEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = DeviceIntelligenceEngine(db_path=db_path)
    return _ENGINE


def identify_device(observation: Dict[str, Any], db_path: Optional[str] = None) -> Dict[str, Any]:
    engine = get_device_intelligence_engine(db_path=db_path)
    return engine.identify(observation)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = DeviceIntelligenceEngine()

    sample_observation = {
        "center_freq_mhz": 2440.0,
        "rf_band": "2.4GHz",
        "channel": 20,
        "bandwidth_khz": 2000,
        "modulation": "OQPSK",
        "protocol_family": "Zigbee",
        "protocol": "zigbee",
        "protocol_subtype": "door_sensor",
        "vendor_hint": "aqara",
        "burst_interval_ms": 2400,
        "burst_duration_ms": 8,
        "signal_stability": 0.87,
        "shape_hint": "narrowband_burst",
        "frame_structure": "telemetry_burst",
    }

    result = engine.identify(sample_observation)
    print(yaml.safe_dump(result, sort_keys=False, default_flow_style=False))
