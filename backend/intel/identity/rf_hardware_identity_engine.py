# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/rf_hardware_identity_engine.py
# VERSION:      v3.0.0 (PHASE-2 RF HARDWARE IDENTITY ENGINE)
# LAST UPDATED: 2026-03-15
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# RFHardwareIdentityEngine identifies recurring physical transmitters by
# analyzing subtle analog RF imperfections visible through IQ-derived features.
#
# Unlike device classification, which answers:
#
#     "What kind of device is this?"
#
# hardware identity answers:
#
#     "Is this the same physical transmitter we saw before?"
#
# This is a Phase-2 identity layer for GhostRecon. It is designed to support:
#
#   • repeated transmitter recognition
#   • short-term / medium-term persistence tracking
#   • passive RF fingerprint correlation
#   • hardware-level clustering under imperfect observations
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# ReconEngine / FeatureExtractor
#      ↓
# SignalEngine
#      ↓
# RFHardwareIdentityEngine (THIS FILE)
#      ├ feature sanitation
#      ├ fingerprint vector extraction
#      ├ weighted similarity scoring
#      ├ adaptive identity update
#      ├ identity store maintenance
#      └ confidence / explainability output
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# RFHardwareIdentityEngine IS responsible for:
#
#   • extracting hardware fingerprint vectors from RF features
#   • matching signals against prior hardware identities
#   • assigning stable hardware IDs
#   • updating identity prototypes over time
#   • pruning stale identities
#   • exposing similarity / evidence metadata
#
# RFHardwareIdentityEngine is NOT responsible for:
#
#   • device-type classification
#   • vendor inference
#   • packet decoding
#   • SDR control
#   • long-term disk persistence
#   • vulnerability assessment
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PASSIVE RF ONLY
# -----------------------------------------------------------------------------
# Uses passive analog-layer observables only.
#
# 2. ROBUST TO PARTIAL FEATURES
# -----------------------------------------------------------------------------
# Real signals often miss one or more fingerprint dimensions. The engine
# tolerates sparse feature observations and avoids over-trusting empty vectors.
#
# 3. WEIGHTED MATCHING
# -----------------------------------------------------------------------------
# More stable physical traits contribute more heavily than weak or noisy traits.
#
# 4. IDENTITY PROTOTYPE REFINEMENT
# -----------------------------------------------------------------------------
# Stored hardware fingerprints are updated incrementally as more observations
# arrive, improving stability over time.
#
# 5. SAFE CONSERVATISM
# -----------------------------------------------------------------------------
# Weak evidence should create a new tentative identity rather than incorrectly
# merging two different physical transmitters.
#
# 6. EXPLAINABILITY
# -----------------------------------------------------------------------------
# Return payloads include match confidence, contributing dimensions, and
# identity statistics for tuning.
#
# =============================================================================

from __future__ import annotations

import hashlib
import math
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class RFHardwareIdentityEngine:
    """
    Phase-2 RF hardware identity engine.

    Input:
        signal: dict containing rf_features and optional signal metadata

    Output:
        dict with stable hardware identity fields
    """

    ENGINE_VERSION = "3.0.0"

    # Conservative threshold for physical transmitter matching
    SIMILARITY_THRESHOLD = 0.935

    # Below this threshold, identity is treated as weak / tentative
    CONFIDENT_MATCH_THRESHOLD = 0.965

    # Store limits / maintenance
    MAX_IDENTITIES = 5000
    STALE_IDENTITY_SECONDS = 60 * 60 * 6  # 6 hours
    MIN_FEATURES_REQUIRED = 3

    # EMA update factor for stored prototypes
    PROTOTYPE_ALPHA = 0.18

    # Weighted fingerprint dimensions
    FEATURE_SPECS = [
        ("cfo_estimate", 1.25, 50000.0),
        ("phase_noise", 1.10, 50.0),
        ("freq_deviation_estimate", 1.00, 200000.0),
        ("inst_freq_jitter_std", 1.05, 50000.0),
        ("oscillator_drift_slope", 1.15, 10000.0),
        ("stability_score", 0.75, 1.0),
        ("iq_imbalance", 0.80, 1.0),
        ("dc_offset", 0.60, 1.0),
    ]

    # -------------------------------------------------------------------------
    # INIT
    # -------------------------------------------------------------------------

    def __init__(self) -> None:
        self.identity_store: Dict[str, Dict[str, Any]] = {}

    # -------------------------------------------------------------------------
    # MAIN ENTRY
    # -------------------------------------------------------------------------

    def identify(self, signal: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        now = time.time()
        self._prune_stale_identities(now)

        vector, mask, explain = self._extract_vector(signal)

        if vector is None or mask is None:
            return None

        observed_count = int(np.sum(mask))
        if observed_count < self.MIN_FEATURES_REQUIRED:
            return {
                "hardware_id": None,
                "hardware_confidence": 0.0,
                "hardware_similarity": 0.0,
                "hardware_status": "insufficient_fingerprint_features",
                "hardware_features_observed": observed_count,
                "hardware_engine_version": self.ENGINE_VERSION,
                "hardware_explain": explain,
            }

        best_id = None
        best_score = -1.0
        best_detail = None

        for hid, stored in self.identity_store.items():
            score, detail = self._similarity(
                vector_a=vector,
                mask_a=mask,
                vector_b=stored["vector"],
                mask_b=stored["mask"],
            )

            if score > best_score:
                best_score = score
                best_id = hid
                best_detail = detail

        if best_id and best_score >= self.SIMILARITY_THRESHOLD:
            self._update_identity(best_id, vector, mask, now)

            stored = self.identity_store[best_id]
            confidence = self._similarity_to_confidence(best_score, observed_count)

            return {
                "hardware_id": best_id,
                "hardware_similarity": round(best_score, 4),
                "hardware_confidence": round(confidence, 4),
                "hardware_status": (
                    "matched_confirmed"
                    if best_score >= self.CONFIDENT_MATCH_THRESHOLD
                    else "matched_probable"
                ),
                "hardware_features_observed": observed_count,
                "hardware_seen_count": stored["seen_count"],
                "hardware_first_seen": stored["first_seen"],
                "hardware_last_seen": stored["last_seen"],
                "hardware_engine_version": self.ENGINE_VERSION,
                "hardware_explain": {
                    **explain,
                    "match_detail": best_detail,
                    "store_size": len(self.identity_store),
                },
            }

        new_id = self._create_identity(vector, mask, now, signal)
        confidence = self._new_identity_confidence(observed_count, explain)

        return {
            "hardware_id": new_id,
            "hardware_similarity": 1.0,
            "hardware_confidence": round(confidence, 4),
            "hardware_status": "new_identity_created",
            "hardware_features_observed": observed_count,
            "hardware_seen_count": self.identity_store[new_id]["seen_count"],
            "hardware_first_seen": self.identity_store[new_id]["first_seen"],
            "hardware_last_seen": self.identity_store[new_id]["last_seen"],
            "hardware_engine_version": self.ENGINE_VERSION,
            "hardware_explain": {
                **explain,
                "reason": "no_existing_identity_above_threshold",
                "best_candidate_id": best_id,
                "best_candidate_similarity": round(best_score, 4) if best_score >= 0 else None,
                "best_candidate_detail": best_detail,
                "store_size": len(self.identity_store),
            },
        }

    # -------------------------------------------------------------------------
    # FEATURE EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_vector(
        self, signal: Dict[str, Any]
    ) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], Dict[str, Any]]:
        rf = signal.get("rf_features", {}) or {}

        values: List[float] = []
        mask: List[float] = []
        observed_keys: List[str] = []
        missing_keys: List[str] = []

        for key, weight, scale in self.FEATURE_SPECS:
            raw = self._first_non_null(
                rf,
                key,
                self._legacy_alias(key),
            )

            value = self._safe_float(raw, None)

            if value is None or not math.isfinite(value):
                values.append(0.0)
                mask.append(0.0)
                missing_keys.append(key)
                continue

            clamped = self._clamp(value / scale, -3.0, 3.0)
            weighted = clamped * weight

            values.append(weighted)
            mask.append(1.0)
            observed_keys.append(key)

        vector = np.array(values, dtype=float)
        mask_vec = np.array(mask, dtype=float)

        if np.sum(mask_vec) == 0:
            return None, None, {
                "observed_features": [],
                "missing_features": [k for k, _, _ in self.FEATURE_SPECS],
                "feature_quality": "empty",
            }

        normalized = self._masked_normalize(vector, mask_vec)

        explain = {
            "observed_features": observed_keys,
            "missing_features": missing_keys,
            "feature_quality": self._feature_quality_label(int(np.sum(mask_vec))),
            "raw_vector_dimensions": len(values),
        }

        return normalized, mask_vec, explain

    # -------------------------------------------------------------------------
    # SIMILARITY
    # -------------------------------------------------------------------------

    def _similarity(
        self,
        vector_a: np.ndarray,
        mask_a: np.ndarray,
        vector_b: np.ndarray,
        mask_b: np.ndarray,
    ) -> Tuple[float, Dict[str, Any]]:
        overlap = mask_a * mask_b
        overlap_count = int(np.sum(overlap))

        if overlap_count < self.MIN_FEATURES_REQUIRED:
            return 0.0, {
                "overlap_features": overlap_count,
                "reason": "insufficient_overlap",
            }

        a = vector_a * overlap
        b = vector_b * overlap

        denom = np.linalg.norm(a) * np.linalg.norm(b)
        if denom == 0:
            return 0.0, {
                "overlap_features": overlap_count,
                "reason": "zero_norm_overlap",
            }

        cosine = float(np.dot(a, b) / denom)

        # Penalize low-overlap comparisons
        overlap_ratio = overlap_count / float(len(self.FEATURE_SPECS))
        adjusted = cosine * (0.72 + 0.28 * overlap_ratio)

        return max(0.0, min(1.0, adjusted)), {
            "cosine_similarity": round(cosine, 5),
            "adjusted_similarity": round(adjusted, 5),
            "overlap_features": overlap_count,
            "overlap_ratio": round(overlap_ratio, 5),
        }

    # -------------------------------------------------------------------------
    # IDENTITY STORE MANAGEMENT
    # -------------------------------------------------------------------------

    def _create_identity(
        self,
        vector: np.ndarray,
        mask: np.ndarray,
        now: float,
        signal: Dict[str, Any],
    ) -> str:
        if len(self.identity_store) >= self.MAX_IDENTITIES:
            self._evict_oldest_identity()

        new_id = self._hash_vector(vector, mask, signal)

        # Ensure uniqueness even if hashed candidate already exists
        suffix = 1
        base_id = new_id
        while new_id in self.identity_store:
            new_id = f"{base_id}_{suffix}"
            suffix += 1

        self.identity_store[new_id] = {
            "vector": vector.copy(),
            "mask": mask.copy(),
            "first_seen": now,
            "last_seen": now,
            "seen_count": 1,
        }
        return new_id

    def _update_identity(
        self,
        hardware_id: str,
        vector: np.ndarray,
        mask: np.ndarray,
        now: float,
    ) -> None:
        stored = self.identity_store[hardware_id]

        merged_mask = np.maximum(stored["mask"], mask)

        # EMA update only on overlapping observed dimensions
        updated_vector = stored["vector"].copy()
        for idx in range(len(updated_vector)):
            if mask[idx] > 0:
                updated_vector[idx] = (
                    (1.0 - self.PROTOTYPE_ALPHA) * stored["vector"][idx]
                    + self.PROTOTYPE_ALPHA * vector[idx]
                )

        updated_vector = self._masked_normalize(updated_vector, merged_mask)

        stored["vector"] = updated_vector
        stored["mask"] = merged_mask
        stored["last_seen"] = now
        stored["seen_count"] += 1

    def _prune_stale_identities(self, now: float) -> None:
        stale_ids = [
            hid
            for hid, data in self.identity_store.items()
            if (now - float(data.get("last_seen", now))) > self.STALE_IDENTITY_SECONDS
        ]
        for hid in stale_ids:
            self.identity_store.pop(hid, None)

    def _evict_oldest_identity(self) -> None:
        if not self.identity_store:
            return

        oldest_id = min(
            self.identity_store.items(),
            key=lambda item: (
                float(item[1].get("last_seen", 0.0)),
                float(item[1].get("seen_count", 0)),
            ),
        )[0]
        self.identity_store.pop(oldest_id, None)

    # -------------------------------------------------------------------------
    # HASHING
    # -------------------------------------------------------------------------

    def _hash_vector(
        self,
        vector: np.ndarray,
        mask: np.ndarray,
        signal: Dict[str, Any],
    ) -> str:
        freq_hint = self._safe_float(
            signal.get("freq_mhz") or signal.get("frequency_mhz"),
            0.0,
        )
        proto_hint = str(signal.get("protocol_signature") or "").upper().strip()

        rounded_vector = np.round(vector, 4)
        rounded_mask = np.round(mask, 1)

        material = (
            rounded_vector.tobytes()
            + rounded_mask.tobytes()
            + str(round(freq_hint, 2)).encode("utf-8")
            + proto_hint.encode("utf-8")
        )

        return hashlib.sha256(material).hexdigest()[:18]

    # -------------------------------------------------------------------------
    # CONFIDENCE
    # -------------------------------------------------------------------------

    def _similarity_to_confidence(self, similarity: float, observed_count: int) -> float:
        feature_factor = min(1.0, observed_count / float(len(self.FEATURE_SPECS)))
        return max(0.0, min(1.0, (similarity * 0.82) + (feature_factor * 0.18)))

    def _new_identity_confidence(self, observed_count: int, explain: Dict[str, Any]) -> float:
        quality = explain.get("feature_quality")
        base = {
            "weak": 0.42,
            "fair": 0.56,
            "good": 0.68,
            "strong": 0.78,
        }.get(quality, 0.50)

        feature_factor = min(1.0, observed_count / float(len(self.FEATURE_SPECS)))
        return min(0.85, base * 0.7 + feature_factor * 0.3)

    # -------------------------------------------------------------------------
    # VECTOR UTILITIES
    # -------------------------------------------------------------------------

    def _masked_normalize(self, vector: np.ndarray, mask: np.ndarray) -> np.ndarray:
        masked = vector * mask
        norm = np.linalg.norm(masked)
        if norm == 0:
            return masked
        return masked / norm

    def _feature_quality_label(self, observed_count: int) -> str:
        if observed_count <= 2:
            return "weak"
        if observed_count <= 4:
            return "fair"
        if observed_count <= 6:
            return "good"
        return "strong"

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    def _legacy_alias(self, key: str) -> str:
        aliases = {
            "cfo_estimate": "carrier_offset_hz",
            "phase_noise": "phase_noise_estimate",
            "freq_deviation_estimate": "frequency_deviation",
            "inst_freq_jitter_std": "instantaneous_frequency_jitter_std",
            "oscillator_drift_slope": "drift_slope",
            "stability_score": "signal_stability_score",
            "iq_imbalance": "iq_gain_imbalance",
            "dc_offset": "dc_bias",
        }
        return aliases.get(key, key)

    def _first_non_null(self, data: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in data and data.get(key) is not None:
                return data.get(key)
        return None

    def _safe_float(self, value: Any, default: Optional[float] = 0.0) -> Optional[float]:
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    def _clamp(self, value: float, low: float, high: float) -> float:
        return max(low, min(high, value))
