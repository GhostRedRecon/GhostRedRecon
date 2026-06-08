# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/signal_engine.py
# VERSION:      v47.0.0 (FINAL LOCKED - SIGINT SIGNAL / EMITTER CORE)
# UPDATED:      2026-03-22
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# FULL PIPELINE
# -----------------------------------------------------------------------------
# SDR / HackRF
#     ↓
# LiveFFT
#     ↓
# ReconEngine (adaptive spectral + burst detection)
#     ↓
# SignalEngine  ← THIS FILE
#     ├── Input Validation Layer
#     ├── Stable Signal Registry Layer
#     ├── Feature Enrichment Layer
#     ├── Protocol Inference Layer
#     ├── Confidence Fusion Layer
#     ├── Lifecycle Management Layer
#     ├── Emitter Aggregation Layer
#     ├── Device Fusion Export Layer
#     ├── Device Context Feedback Layer
#     └── API / Summary Export Layer
#     ↓
# DeviceFusion / Device Intelligence / API
#
# -----------------------------------------------------------------------------
# HIGH-LEVEL ROLE
# -----------------------------------------------------------------------------
# SignalEngine is the stateful RF intelligence core.
#
# It converts:
#   normalized detections → persistent tracked signals → grouped emitters
#
# ReconEngine answers:
#   "RF activity exists at frequency X"
#
# SignalEngine answers:
#   "this recurring RF entity persisted over time, carries a protocol hypothesis,
#    confidence, priority, emitter grouping, and optional fused device context"
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Maintain persistent RF signal continuity across time.
#
# Provide:
#   ✔ stable signal identity
#   ✔ protocol hypothesis + confidence
#   ✔ recency / persistence scoring
#   ✔ emitter grouping
#   ✔ downstream device-fusion export
#   ✔ validator-visible device hints
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Accept normalized signal updates from ReconEngine
# ✔ Normalize frequency into stable signal IDs
# ✔ Preserve lifecycle state (active / stale)
# ✔ Track power / hit count / update count / recency
# ✔ Preserve RF metadata without breaking downstream APIs
#
# PHASE 2 RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Enrich signals with SignalFeatureBuilder output
# ✔ Run fast protocol classification safely
# ✔ Run protocol fusion engine safely
# ✔ Merge classifier + fusion results conservatively
# ✔ Prefer weak-but-useful protocol truth over UNKNOWN collapse
#
# PHASE 3 RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Group active signals into emitters
# ✔ Export signal / emitter views to DeviceFusion
# ✔ Apply fused device context back onto signals
# ✔ Preserve signal ownership while adding device hints
#
# API RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Expose stable getters for signals
# ✔ Expose top signals / summaries / stats / state
# ✔ Preserve backward-compatible helper names used by older API code
#
# =============================================================================
# ❌ NON-RESPONSIBILITIES
# =============================================================================
#
# ✘ SDR hardware control
# ✘ FFT generation
# ✘ Burst extraction
# ✘ Final packet decoding
# ✘ Definitive vendor / product certainty
# ✘ TX / attack logic
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. ZERO BREAKAGE
# -----------------------------------------------------------------------------
# Existing callers must continue to work:
#   start()
#   stop()
#   update_signal()
#   get_active_signals()
#   get_all_signals()
#   get_top_signals()
#   get_stats()
#
# 2. RECON IS DETECTION TRUTH
# -----------------------------------------------------------------------------
# Incoming detection confidence from ReconEngine is consumed and fused, not
# discarded.
#
# 3. SIGNAL REGISTRY IS SOURCE OF TRUTH
# -----------------------------------------------------------------------------
# Signals remain signal-owned entities; device hints are additive only.
#
# 4. FAIL-SAFE INTELLIGENCE
# -----------------------------------------------------------------------------
# Feature extraction, protocol inference, and fusion feedback must never crash
# the registry.
#
# 5. THREAD SAFE
# -----------------------------------------------------------------------------
# All mutable shared state is protected by a lock.
#
# 6. OPERATOR-FIRST OUTPUT
# -----------------------------------------------------------------------------
# Returned objects must be directly usable by APIs, validators, and UI layers.
#
# 7. CONTROLLED MEMORY
# -----------------------------------------------------------------------------
# Metadata is bounded to avoid unbounded growth.
#
# =============================================================================
# 📦 INPUT SCHEMA
# =============================================================================
#
# update_signal(
#     sid: str,
#     freq_mhz: float,
#     power_db: float,
#     metadata: Optional[dict]
# )
#
# Incoming metadata may include Recon v52 fields such as:
#   confidence
#   rf_band
#   engine
#   cluster_size
#   power_margin
#   temporal_consistency
#   peak_density
#   bandwidth_estimate_mhz
#   bandwidth_class
#   spectral_flatness
#   edge_steepness
#   shape_score
#   signal_type
#   burst_ratio
#   periodicity
#   freq_variance
#
# =============================================================================
# 📤 OUTPUT SCHEMA
# =============================================================================
#
# {
#   "signal_id": str,
#   "source_sid": str,
#   "first_seen": float,
#   "last_seen": float,
#   "frequency_mhz": float,
#   "power_db": float,
#   "avg_power_db": float,
#   "max_power": float,
#   "updates": int,
#   "hit_count": int,
#   "active": bool,
#   "state": "active" | "stale",
#   "protocol": str,
#   "protocol_confidence": float,
#   "rf_protocol": Optional[str],
#   "rf_protocol_confidence": float,
#   "signal_confidence": float,
#   "confidence": float,
#   "quality_score": float,
#   "priority_score": float,
#   "promoted": bool,
#   "rf_band": Optional[str],
#   "engine": Optional[str],
#   "device_id": Optional[str],
#   "device_type": Optional[str],
#   "device_category": Optional[str],
#   "device_confidence": float,
#   "age_sec": float,
#   "last_seen_age_sec": float,
#   "metadata": dict
# }
#
# =============================================================================
# 🔍 DETECTION / INTELLIGENCE BEHAVIOR
# =============================================================================
#
# 1. Validate input
# 2. Enrich features
# 3. Run fast protocol classifier
# 4. Run protocol fusion engine
# 5. Merge classifier + fusion conservatively:
#      - trust fast classifier by default
#      - only let fusion override when stronger and clearer
# 6. Normalize frequency → stable signal ID
# 7. Update signal record
# 8. Fuse recon confidence + persistence/recency confidence
# 9. Refresh lifecycle state
# 10. Export to fusion and optionally apply device feedback
#
# =============================================================================
# 🔄 CHANGES IN v47.0.0
# =============================================================================
#
# ✔ Preserved update_signal(...) contract
# ✔ Restored full state / summary / compatibility helper surface
# ✔ Fixed lifecycle handling (refresh now works outside ingest too)
# ✔ Fixed protocol merge policy so ProtocolEngine does not blindly erase useful
#   fast-classifier truth
# ✔ Preserved Recon confidence as first-class input
# ✔ Restored emitter grouping and device feedback helpers
# ✔ Added optional fusion feedback loop
# ✔ Added bounded metadata and additive hint preservation
#
# =============================================================================

from __future__ import annotations

import copy
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from backend.intel.signal_features import SignalFeatureBuilder
from backend.intel.protocol.protocol_classifier import ProtocolClassifier
from backend.intel.protocol.protocol_engine import ProtocolEngine

log = logging.getLogger("ghostrecon.signal")


class SignalEngine:

    VERSION = "47.0.0"

    # -------------------------------------------------------------------------
    # Signal lifecycle tuning
    # -------------------------------------------------------------------------
    STALE_TIMEOUT_SEC = 15.0
    PRUNE_TIMEOUT_SEC = 60.0
    ID_RESOLUTION_MHZ = 0.2

    # -------------------------------------------------------------------------
    # Emitter grouping tuning
    # -------------------------------------------------------------------------
    EMITTER_GROUP_TOLERANCE_MHZ = 0.8
    WIFI_TOLERANCE_MHZ = 3.0
    ZIGBEE_TOLERANCE_MHZ = 1.2

    # -------------------------------------------------------------------------
    # Confidence / promotion tuning
    # -------------------------------------------------------------------------
    MAX_PERSISTENCE_UPDATES = 15
    REAL_PROTOCOL_THRESHOLD = 0.25

    # -------------------------------------------------------------------------
    # Fusion / metadata tuning
    # -------------------------------------------------------------------------
    FUSION_REFRESH_INTERVAL_SEC = 1.0
    MAX_METADATA_KEYS = 80
    LORA_CENTER_HINTS = (
        433.175, 433.375, 433.775, 433.92,
        867.1, 867.3, 867.5, 867.7, 867.9,
        868.1, 868.3, 868.5, 869.525,
        903.9, 904.1, 904.3, 904.5, 904.7, 904.9, 905.1, 905.3,
        923.3,
    )

    def __init__(self):

        self._signals: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._lock = threading.Lock()
        self._updates_processed = 0

        self._device_fusion = None
        self._last_fusion_refresh_ts = 0.0

        self._feature_builder = SignalFeatureBuilder()
        self._classifier = ProtocolClassifier()
        self._protocol_engine = ProtocolEngine()

        print(f"🧠 [SIGNAL] Initialized | ID={id(self)}")
        log.info("[SIGNAL] Initialized | ID=%s", id(self))

    # =========================================================================
    # CONTROL
    # =========================================================================
    def start(self):
        with self._lock:
            self._running = True
            self._signals.clear()
            self._updates_processed = 0
            self._last_fusion_refresh_ts = 0.0

        print("🟢 [SIGNAL] STARTED")
        log.info("[SIGNAL] Engine started")

    def stop(self):
        with self._lock:
            self._running = False
            self._signals.clear()

        print("🔴 [SIGNAL] STOPPED")
        log.info("[SIGNAL] Engine stopped")

    def reset(self):
        with self._lock:
            self._signals.clear()
            self._updates_processed = 0
            self._last_fusion_refresh_ts = 0.0

        log.info("[SIGNAL] Cache reset")

    def _prune_stale_signals(self, now: float) -> None:
        stale_ids = []
        for signal_id, signal in self._signals.items():
            last_seen = self._safe_float(signal.get("last_seen"), now)
            if (now - last_seen) > self.PRUNE_TIMEOUT_SEC:
                stale_ids.append(signal_id)
        for signal_id in stale_ids:
            self._signals.pop(signal_id, None)

    @property
    def running(self):
        return self._running

    def set_device_fusion(self, fusion_engine):
        self._device_fusion = fusion_engine

    # =========================================================================
    # INGEST
    # =========================================================================
    def update_signal(self, sid, freq_mhz, power_db, metadata=None):

        if not self._running:
            return

        try:
            freq = float(freq_mhz)
            power = float(power_db)
        except Exception:
            return

        if freq <= 0:
            return

        now = time.time()
        meta = metadata.copy() if isinstance(metadata, dict) else {}

        # ---------------------------------------------------------------------
        # Feature enrichment
        # ---------------------------------------------------------------------
        try:
            features = self._feature_builder.update(
                signal_id=str(sid),
                freq_mhz=freq,
                power_db=power,
                metadata=meta,
            )
            if isinstance(features, dict):
                meta.update(features)
        except Exception as e:
            log.debug("[SIGNAL] Feature extraction failed: %s", e)

        meta = self._normalize_rf_context(freq, meta)
        meta = self._refresh_subghz_phy_hints(freq, meta)

        # ---------------------------------------------------------------------
        # Protocol inference
        # ---------------------------------------------------------------------
        protocol_fields = self._classify_signal(freq, power, meta)
        if isinstance(protocol_fields, dict):
            meta.update(protocol_fields)

        meta = self._normalize_rf_context(freq, meta)
        meta = self._refresh_subghz_phy_hints(freq, meta)

        # ---------------------------------------------------------------------
        # Stable ID
        # ---------------------------------------------------------------------
        stable_freq = round(freq / self.ID_RESOLUTION_MHZ) * self.ID_RESOLUTION_MHZ
        stable_id = f"{stable_freq:.3f}"

        incoming_conf = self._safe_float(meta.get("confidence"), 0.0)
        fusion_refresh_needed = False

        with self._lock:

            if stable_id not in self._signals:
                self._signals[stable_id] = {
                    "signal_id": stable_id,
                    "source_sid": str(sid),
                    "first_seen": now,
                    "last_seen": now,
                    "updates": 0,
                    "hit_count": 0,
                    "frequency_mhz": stable_freq,
                    "power_db": power,
                    "avg_power_db": power,
                    "max_power": power,
                    "active": True,
                    "state": "active",
                    "protocol": "UNKNOWN_PROTOCOL",
                    "protocol_confidence": 0.0,
                    "rf_protocol": None,
                    "rf_protocol_confidence": 0.0,
                    "signal_confidence": 0.0,
                    "confidence": 0.0,
                    "quality_score": 0.0,
                    "priority_score": power,
                    "promoted": False,
                    "rf_band": None,
                    "engine": None,
                    "device_id": None,
                    "device_type": None,
                    "device_category": None,
                    "device_confidence": 0.0,
                    "age_sec": 0.0,
                    "last_seen_age_sec": 0.0,
                    "metadata": {},
                }

            entry = self._signals[stable_id]

            self._updates_processed += 1
            entry["updates"] += 1
            entry["hit_count"] = entry["updates"]
            entry["last_seen"] = now
            entry["source_sid"] = str(sid)
            entry["frequency_mhz"] = stable_freq
            entry["power_db"] = power
            entry["max_power"] = max(self._safe_float(entry.get("max_power"), power), power)
            entry["avg_power_db"] = self._rolling_avg(
                self._safe_float(entry.get("avg_power_db"), power),
                power,
                int(entry["updates"]),
            )

            # Preserve additive recon / RF context
            entry["rf_band"] = meta.get("rf_band", meta.get("band", entry.get("rf_band")))
            entry["engine"] = meta.get("engine", entry.get("engine"))

            # Preserve optional hint fields from upstream / later layers
            for hint_key in [
                "vendor",
                "manufacturer",
                "device",
                "device_name",
                "device_role_hint",
                "product_category_hint",
                "behavior_profile_hint",
                "rf_device_class",
                "channel",
                "channel_family",
                "channel_confidence",
                "zigbee_channel",
                "ble_channel",
                "wifi_channel",
                "burst_ratio",
                "periodicity",
                "burst_recurrence_score",
                "subghz_periodicity",
                "subghz_burst_ratio",
                "lora_role_hint",
                "lora_role_confidence",
                "lora_role",
                "lora_operating_mode_hint",
                "lora_device_type_hint",
                "lora_device_type_confidence",
                "lora_network_region",
                "lora_bandplan",
                "lora_bandplan_confidence",
                "lora_cadence_class",
                "lora_identity_family",
                "lora_identity_evidence",
                "lora_mesh_like",
                "lora_meter_like",
                "lora_lorawan_like",
                "lora_mesh_score",
                "lora_meter_score",
                "lora_industrial_score",
                "lora_gateway_score",
                "lora_dwell_span_mhz",
                "lora_frequency_count",
                "subghz_role",
                "subghz_role_confidence",
                "subghz_operating_mode_hint",
                "subghz_profile",
                "subghz_recurring_like",
                "subghz_recurrence_confidence",
                "zigbee_role",
                "zigbee_role_confidence",
                "zigbee_operating_mode_hint",
                "zigbee_mesh_like",
                "correlation_entity_id",
                "correlation_confidence",
                "correlation_protocols",
                "freq_variance",
                "signal_type",
                "rf_ble_adv_distance_mhz",
                "rf_burst_periodicity",
                "rf_duty_cycle",
                "rf_modulation_hint",
                "rf_chirp_detected",
                "rf_frame_structure",
                "rf_frame_protocol_hint",
                "rf_frame_confidence",
                "symbol_rate_estimate",
                "rf_symbol_rate_estimate",
                "rf_burst_duration_ms",
                "avg_burst_duration_ms",
                "burst_interval_ms",
                "spectral_chirp_hint",
                "rf_temporal_profile",
                "rf_signal_class",
                "rf_classifier_readiness",
                "rf_feature_completeness",
                "rf_observation_count",
                "rf_identity_continuity_score",
                "bandwidth_estimate_mhz",
                "bandwidth_class",
                "peak_density",
                "temporal_consistency",
                "spectral_flatness",
                "edge_steepness",
                "shape_score",
                "protocol_candidates",
                "ranked_protocol_candidates",
                "protocol_score_map",
                "protocol_evidence",
                "protocol_penalty_map",
                "protocol_ambiguity",
            ]:
                if hint_key in meta:
                    entry[hint_key] = meta.get(hint_key)

            # Protocol result
            entry["protocol"] = protocol_fields.get("protocol", entry.get("protocol", "UNKNOWN_PROTOCOL"))
            entry["protocol_confidence"] = self._safe_float(
                protocol_fields.get("protocol_confidence", entry.get("protocol_confidence", 0.0)),
                0.0,
            )
            entry["rf_protocol"] = protocol_fields.get("rf_protocol", entry.get("rf_protocol"))
            entry["rf_protocol_confidence"] = self._safe_float(
                protocol_fields.get("rf_protocol_confidence", entry.get("rf_protocol_confidence", 0.0)),
                0.0,
            )

            # Confidence fusion: Recon truth + persistence/recency model
            base_conf = self._compute_signal_confidence(entry, now)
            entry["signal_confidence"] = max(base_conf, incoming_conf)
            entry["confidence"] = max(
                self._safe_float(entry.get("signal_confidence"), 0.0),
                self._safe_float(entry.get("protocol_confidence"), 0.0),
            )

            # Quality / priority / promotion
            entry["quality_score"] = round(
                (entry["signal_confidence"] * 0.70) + (entry["protocol_confidence"] * 0.30),
                4,
            )
            entry["priority_score"] = round(
                self._safe_float(entry["max_power"], -120.0) + (entry["signal_confidence"] * 10.0),
                4,
            )
            entry["promoted"] = bool(entry["confidence"] >= 0.60)
            entry["is_real_protocol"] = bool(
                entry["protocol"] != "UNKNOWN_PROTOCOL"
                and entry["protocol_confidence"] >= self.REAL_PROTOCOL_THRESHOLD
            )

            # Lifecycle refresh
            self._refresh_entry_state(entry, now)

            # Safe metadata snapshot
            entry["metadata"] = self._safe_metadata(meta)

            # Throttled fusion refresh
            if self._device_fusion and (now - self._last_fusion_refresh_ts) >= self.FUSION_REFRESH_INTERVAL_SEC:
                self._last_fusion_refresh_ts = now
                fusion_refresh_needed = True

        # ---------------------------------------------------------------------
        # Fusion export / feedback outside lock
        # ---------------------------------------------------------------------
        if self._device_fusion and fusion_refresh_needed:
            try:
                emitters = self.get_active_emitters()
                if emitters:
                    result = self._device_fusion.fuse(emitters)

                    if isinstance(result, list) and result:
                        self.update_device_context(result)
                    elif hasattr(self._device_fusion, "get_devices"):
                        devices = self._device_fusion.get_devices()
                        if isinstance(devices, list) and devices:
                            self.update_device_context(devices)
            except Exception as e:
                log.debug("[SIGNAL] Fusion export/feedback failed: %s", e)

    # =========================================================================
    # PROTOCOL
    # =========================================================================
    def _classify_signal(self, freq, power, meta):
        """
        Conservative protocol merge policy:

        - Trust fast classifier by default.
        - Allow ProtocolEngine to override only when it provides stronger,
          clearer evidence than the fast classifier.
        - Preserve fallback to protocol candidates when available.
        """
        try:
            fast = self._classifier.classify(meta)
            if not isinstance(fast, dict):
                fast = {}

            fusion = self._protocol_engine.classify(meta)
            if not isinstance(fusion, dict):
                fusion = {}

            fast_protocol = fast.get("protocol", "UNKNOWN_PROTOCOL")
            fast_conf = self._safe_float(fast.get("protocol_confidence"), 0.0)

            fusion_protocol = fusion.get("protocol", "UNKNOWN_PROTOCOL")
            fusion_conf = self._safe_float(fusion.get("protocol_confidence"), 0.0)

            # Default to fast classifier
            final = {
                "protocol": fast_protocol or "UNKNOWN_PROTOCOL",
                "protocol_confidence": fast_conf,
                "rf_protocol": fast.get("rf_protocol"),
                "rf_protocol_confidence": self._safe_float(fast.get("rf_protocol_confidence"), 0.0),
            }

            # Let fusion override only when genuinely stronger
            if (
                fusion_protocol
                and fusion_protocol != "UNKNOWN_PROTOCOL"
                and (
                    final["protocol"] == "UNKNOWN_PROTOCOL"
                    or fusion_conf >= max(final["protocol_confidence"] + 0.10, 0.35)
                )
            ):
                final["protocol"] = fusion_protocol
                final["protocol_confidence"] = fusion_conf
                final["rf_protocol"] = fusion.get("rf_protocol", final.get("rf_protocol"))
                final["rf_protocol_confidence"] = self._safe_float(
                    fusion.get("rf_protocol_confidence"),
                    final.get("rf_protocol_confidence", 0.0),
                )

            # Fallback to protocol_candidates if both remained unknown/weak
            if final["protocol"] == "UNKNOWN_PROTOCOL":
                candidates = meta.get("protocol_candidates") or []
                ranked = meta.get("ranked_protocol_candidates") or []

                if candidates:
                    best = candidates[0]
                    best_score = 0.0

                    if ranked and isinstance(ranked, list) and isinstance(ranked[0], dict):
                        best = ranked[0].get("protocol", best)
                        best_score = self._safe_float(ranked[0].get("score"), 0.0)
                    elif isinstance(best, str):
                        best_score = self._safe_float(meta.get("protocol_confidence"), 0.0)

                    # only promote candidate if meaningful
                    if best and best != "UNKNOWN_PROTOCOL" and best_score >= self.REAL_PROTOCOL_THRESHOLD:
                        final["protocol"] = best
                        final["protocol_confidence"] = best_score

            return final

        except Exception as e:
            log.debug("[SIGNAL] Protocol classification failed: %s", e)
            return {
                "protocol": "UNKNOWN_PROTOCOL",
                "protocol_confidence": 0.0,
                "rf_protocol": None,
                "rf_protocol_confidence": 0.0,
            }

    # =========================================================================
    # DEVICE CONTEXT FEEDBACK
    # =========================================================================
    def update_device_context(self, devices: List[Dict[str, Any]]):
        """
        Apply fused device hints back onto signal registry.

        Matching is frequency-based with tolerant matching against the stable
        signal frequency resolution.
        """
        if not isinstance(devices, list):
            return

        with self._lock:
            for device in devices:
                if not isinstance(device, dict):
                    continue

                device_id = device.get("device_id")
                device_type = device.get("device_type")
                device_category = device.get("device_category")
                device_confidence = self._safe_float(device.get("confidence"), 0.0)
                vendor = device.get("vendor")
                freqs = device.get("frequencies") or []

                if not freqs:
                    continue

                for entry in self._signals.values():
                    signal_freq = self._safe_float(entry.get("frequency_mhz"), None)
                    if signal_freq is None:
                        continue

                    matched = False
                    for f in freqs:
                        ff = self._safe_float(f, None)
                        if ff is None:
                            continue
                        if abs(signal_freq - ff) <= self.ID_RESOLUTION_MHZ:
                            matched = True
                            break

                    if not matched:
                        continue

                    entry["device_id"] = device_id
                    entry["device_type"] = device_type or entry.get("device_type")
                    entry["device_category"] = device_category or entry.get("device_category")
                    entry["device_confidence"] = max(
                        self._safe_float(entry.get("device_confidence"), 0.0),
                        device_confidence,
                    )
                    for field in [
                        "device_role_hint",
                        "device_role_confidence",
                        "product_category_hint",
                        "product_category_confidence",
                        "behavior_profile_hint",
                        "rf_device_class",
                        "ble_role",
                        "ble_role_confidence",
                        "ble_adv_like",
                        "ble_operating_mode_hint",
                        "lora_role",
                        "lora_role_confidence",
                        "lora_operating_mode_hint",
                        "lora_device_type_hint",
                        "lora_device_type_confidence",
                        "lora_network_region",
                        "lora_bandplan",
                        "lora_bandplan_confidence",
                        "lora_cadence_class",
                        "lora_identity_family",
                        "lora_identity_evidence",
                        "lora_mesh_like",
                        "lora_meter_like",
                        "lora_lorawan_like",
                        "lora_mesh_score",
                        "lora_meter_score",
                        "lora_industrial_score",
                        "lora_gateway_score",
                        "lora_dwell_span_mhz",
                        "lora_frequency_count",
                        "subghz_role",
                        "subghz_role_confidence",
                        "subghz_operating_mode_hint",
                        "subghz_profile",
                        "subghz_recurring_like",
                        "subghz_recurrence_confidence",
                        "rf_modulation_hint",
                        "rf_chirp_detected",
                        "rf_frame_structure",
                        "rf_frame_protocol_hint",
                        "rf_frame_confidence",
                        "symbol_rate_estimate",
                        "rf_symbol_rate_estimate",
                        "rf_burst_duration_ms",
                        "avg_burst_duration_ms",
                        "burst_interval_ms",
                        "spectral_chirp_hint",
                        "zigbee_role",
                        "zigbee_role_confidence",
                        "zigbee_operating_mode_hint",
                        "zigbee_mesh_like",
                    ]:
                        if device.get(field) is not None:
                            entry[field] = device.get(field)
                    if vendor:
                        entry["vendor"] = vendor
                    if device.get("correlation_entity_id"):
                        entry["correlation_entity_id"] = device.get("correlation_entity_id")
                    if device.get("correlation_confidence") is not None:
                        entry["correlation_confidence"] = self._safe_float(
                            device.get("correlation_confidence"),
                            self._safe_float(entry.get("correlation_confidence"), 0.0),
                        )
                    if device.get("correlation_protocols"):
                        entry["correlation_protocols"] = list(device.get("correlation_protocols"))

                    meta = entry.get("metadata")
                    if isinstance(meta, dict):
                        meta["device_id"] = entry["device_id"]
                        meta["device_type"] = entry["device_type"]
                        meta["device_category"] = entry["device_category"]
                        meta["device_confidence"] = entry["device_confidence"]
                        for field in [
                            "device_role_hint",
                            "device_role_confidence",
                            "product_category_hint",
                            "product_category_confidence",
                            "behavior_profile_hint",
                            "rf_device_class",
                            "ble_role",
                            "ble_role_confidence",
                            "ble_adv_like",
                            "ble_operating_mode_hint",
                            "lora_role",
                            "lora_role_confidence",
                            "lora_operating_mode_hint",
                            "lora_device_type_hint",
                            "lora_device_type_confidence",
                            "lora_network_region",
                            "lora_bandplan",
                            "lora_bandplan_confidence",
                            "lora_cadence_class",
                            "lora_identity_family",
                            "lora_identity_evidence",
                            "lora_mesh_like",
                            "lora_meter_like",
                            "lora_lorawan_like",
                            "lora_mesh_score",
                            "lora_meter_score",
                            "lora_industrial_score",
                            "lora_gateway_score",
                            "lora_dwell_span_mhz",
                            "lora_frequency_count",
                            "subghz_role",
                            "subghz_role_confidence",
                            "subghz_operating_mode_hint",
                            "subghz_profile",
                            "subghz_recurring_like",
                            "subghz_recurrence_confidence",
                            "rf_modulation_hint",
                            "rf_chirp_detected",
                            "rf_frame_structure",
                            "rf_frame_protocol_hint",
                            "rf_frame_confidence",
                            "spectral_chirp_hint",
                            "zigbee_role",
                            "zigbee_role_confidence",
                            "zigbee_operating_mode_hint",
                            "zigbee_mesh_like",
                        ]:
                            if entry.get(field) is not None:
                                meta[field] = entry.get(field)
                        if vendor:
                            meta["vendor"] = vendor
                        if entry.get("correlation_entity_id"):
                            meta["correlation_entity_id"] = entry["correlation_entity_id"]
                        if entry.get("correlation_protocols"):
                            meta["correlation_protocols"] = list(entry.get("correlation_protocols"))

    def update_correlation_context(self, entities: List[Dict[str, Any]]):
        if not isinstance(entities, list):
            return

        with self._lock:
            for entity in entities:
                if not isinstance(entity, dict):
                    continue

                signal_ids = {str(signal_id) for signal_id in entity.get("signal_ids") or [] if signal_id}
                device_ids = {str(device_id) for device_id in entity.get("device_ids") or [] if device_id}

                if not signal_ids and not device_ids:
                    continue

                for entry in self._signals.values():
                    if (
                        str(entry.get("signal_id")) not in signal_ids
                        and str(entry.get("device_id")) not in device_ids
                    ):
                        continue

                    entry["correlation_entity_id"] = entity.get("entity_id")
                    entry["correlation_confidence"] = self._safe_float(entity.get("confidence"), 0.0)
                    entry["correlation_protocols"] = list(entity.get("protocols") or [])

                    meta = entry.get("metadata")
                    if isinstance(meta, dict):
                        meta["correlation_entity_id"] = entry.get("correlation_entity_id")
                        meta["correlation_confidence"] = entry.get("correlation_confidence")
                        meta["correlation_protocols"] = list(entry.get("correlation_protocols") or [])

    # =========================================================================
    # INTERNAL MODELS
    # =========================================================================
    def _compute_signal_confidence(self, entry, now):
        updates = int(entry.get("updates", 0))
        persistence = min(1.0, updates / float(self.MAX_PERSISTENCE_UPDATES))

        last_seen = self._safe_float(entry.get("last_seen"), now)
        age = max(0.0, now - last_seen)
        recency = max(0.0, 1.0 - (age / float(self.STALE_TIMEOUT_SEC)))

        proto = self._safe_float(entry.get("protocol_confidence"), 0.0)

        return round((0.60 * persistence) + (0.25 * recency) + (0.15 * proto), 4)

    def _normalize_rf_context(self, freq: float, meta: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(meta, dict):
            return {}

        normalized = dict(meta)
        protocol = str(
            normalized.get("protocol")
            or normalized.get("rf_protocol")
            or ""
        ).upper()
        band = str(normalized.get("rf_band") or "").lower()

        wifi_channel = self._coerce_channel(
            normalized.get("wifi_channel"),
            normalized.get("rf_nearest_wifi_channel"),
            self._infer_wifi_channel(freq),
        )
        zigbee_channel = self._coerce_channel(
            normalized.get("zigbee_channel"),
            self._infer_zigbee_channel(freq),
        )
        ble_channel = self._coerce_channel(
            normalized.get("ble_channel"),
            normalized.get("channel") if str(normalized.get("rf_channel_type") or "").lower() == "ble" else None,
            self._infer_ble_channel(freq),
        )

        nearest_family = str(normalized.get("rf_nearest_channel_family") or "").lower()
        rf_channel_type = str(normalized.get("rf_channel_type") or "").lower()
        channel_family = rf_channel_type or nearest_family or self._infer_channel_family(protocol, band, wifi_channel, zigbee_channel, ble_channel)

        if ble_channel == 39 and zigbee_channel == 26:
            if protocol in {"BLE", "BLUETOOTH_LE"} or channel_family == "ble":
                zigbee_channel = None
            elif protocol in {"ZIGBEE", "IEEE_802.15.4", "IEEE_802.15.4_ZIGBEE"} or channel_family == "zigbee":
                ble_channel = None
            else:
                bandwidth_hint = self._safe_float(
                    normalized.get("bandwidth_estimate_mhz", normalized.get("rf_bandwidth_mhz")),
                    0.0,
                )
                if bandwidth_hint >= 1.6:
                    ble_channel = None
                    channel_family = "zigbee"
                else:
                    zigbee_channel = None
                    channel_family = "ble"

        if not normalized.get("wifi_channel") and wifi_channel is not None:
            normalized["wifi_channel"] = wifi_channel
        if not normalized.get("zigbee_channel") and zigbee_channel is not None:
            normalized["zigbee_channel"] = zigbee_channel
        if not normalized.get("ble_channel") and ble_channel is not None:
            normalized["ble_channel"] = ble_channel

        preferred_channel = (
            normalized.get("channel")
            or (wifi_channel if channel_family == "wifi" else None)
            or (zigbee_channel if channel_family == "zigbee" else None)
            or (ble_channel if channel_family == "ble" else None)
        )
        if preferred_channel is not None:
            normalized["channel"] = preferred_channel

        if channel_family:
            normalized["channel_family"] = channel_family

        if "channel_confidence" not in normalized:
            normalized["channel_confidence"] = self._estimate_channel_confidence(freq, channel_family)

        periodicity = self._safe_float(
            normalized.get("periodicity", normalized.get("rf_burst_periodicity")),
            None,
        )
        burst_ratio = self._safe_float(
            normalized.get("burst_ratio", normalized.get("rf_duty_cycle")),
            None,
        )
        if periodicity is not None:
            normalized["periodicity"] = periodicity
            normalized.setdefault("subghz_periodicity", periodicity)
        if burst_ratio is not None:
            normalized["burst_ratio"] = burst_ratio
            normalized.setdefault("subghz_burst_ratio", burst_ratio)
        normalized["burst_recurrence_score"] = self._compute_burst_recurrence_score(
            burst_ratio=burst_ratio,
            periodicity=periodicity,
            temporal_consistency=self._safe_float(normalized.get("temporal_consistency"), 0.0),
            updates=self._safe_float(normalized.get("updates"), 1.0),
        )

        wmbus_like = self._is_wireless_mbus_like(normalized)

        if protocol == "WIRELESS_MBUS" or wmbus_like:
            normalized.setdefault("subghz_role", "meter_endpoint")
            normalized.setdefault("subghz_role_confidence", 0.76 if protocol == "WIRELESS_MBUS" else 0.62)
            normalized.setdefault("subghz_profile", "wireless_mbus_like")
            normalized.setdefault("rf_subghz_profile", "wireless_mbus_like")
            normalized.setdefault("device_type", "Wireless M-Bus Meter")
            normalized.setdefault("device_category", "Utility Meter Endpoint")
            normalized.setdefault("product_category_hint", "wireless_mbus_meter")
            normalized.setdefault("behavior_profile_hint", "metering_endpoint")
            normalized.setdefault("rf_device_class", "Wireless M-Bus Meter")
            normalized.setdefault("subghz_recurring_like", bool(normalized["burst_recurrence_score"] >= 0.35))
            normalized.setdefault("subghz_recurrence_confidence", normalized["burst_recurrence_score"])
        elif protocol == "LORA" or "lora" in band:
            role_hint, role_conf = self._infer_lora_role(normalized)
            normalized.setdefault("lora_role_hint", role_hint)
            normalized.setdefault("lora_role_confidence", role_conf)
            normalized.setdefault("lora_role", role_hint)
            normalized.setdefault("subghz_role", role_hint)
            normalized.setdefault("subghz_role_confidence", role_conf)
            normalized.setdefault("subghz_profile", "lora")
            normalized.setdefault("subghz_recurring_like", bool(normalized["burst_recurrence_score"] >= 0.4))
            normalized.setdefault("subghz_recurrence_confidence", normalized["burst_recurrence_score"])
        elif "subghz" in band or "sub-ghz" in band:
            normalized.setdefault("subghz_profile", "generic_subghz")
            normalized.setdefault("subghz_recurring_like", bool(normalized["burst_recurrence_score"] >= 0.4))
            normalized.setdefault("subghz_recurrence_confidence", normalized["burst_recurrence_score"])

        return normalized

    def _refresh_subghz_phy_hints(self, freq: float, meta: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(meta, dict):
            return {}

        normalized = dict(meta)
        band = str(normalized.get("rf_band") or normalized.get("band") or "").lower()
        if band not in {"subghz", "sub_ghz", "sub-ghz"}:
            return normalized

        bandwidth = self._safe_float(
            normalized.get("bandwidth_estimate_mhz", normalized.get("rf_bandwidth_mhz")),
            0.0,
        )
        peak_density = self._safe_float(normalized.get("peak_density"), 0.0)
        temporal_consistency = self._safe_float(normalized.get("temporal_consistency"), 0.0)
        periodicity = self._safe_float(
            normalized.get("periodicity", normalized.get("rf_burst_periodicity")),
            0.0,
        )
        duty_cycle = self._safe_float(
            normalized.get("burst_ratio", normalized.get("rf_duty_cycle")),
            0.0,
        )
        chirp_hint = self._safe_float(normalized.get("spectral_chirp_hint"), 0.0)
        signal_type = str(normalized.get("signal_type") or "").lower()
        modulation_hint = str(normalized.get("rf_modulation_hint") or "").lower()
        frame_structure = str(normalized.get("rf_frame_structure") or "").lower()
        lora_distance = min(abs(freq - center) for center in self.LORA_CENTER_HINTS)
        wmbus_distance = min(abs(freq - center) for center in (868.30, 868.95, 869.525))

        narrow_subghz = 0.003 <= bandwidth <= 0.60
        periodic_like = signal_type in {"periodic", "burst"} or periodicity >= 0.60 or temporal_consistency >= 0.70
        strong_chirp_like = chirp_hint >= 4.0 and peak_density <= 18.0
        center_aligned = lora_distance <= 0.55
        center_adjacent = lora_distance <= 0.9
        wmbus_center_aligned = wmbus_distance <= 0.18

        if (
            narrow_subghz
            and periodic_like
            and (
                (center_aligned and chirp_hint >= 2.5)
                or (center_adjacent and strong_chirp_like)
            )
            and duty_cycle <= 0.45
        ):
            normalized["rf_modulation_hint"] = "LoRa_like"
            normalized["rf_chirp_detected"] = True
            normalized["rf_frame_structure"] = "chirp"
            normalized["rf_frame_protocol_hint"] = "LoRa"
            normalized["rf_frame_confidence"] = max(
                self._safe_float(normalized.get("rf_frame_confidence"), 0.0),
                round(min(0.92, 0.42 + min(chirp_hint, 6.0) * 0.06 + temporal_consistency * 0.14 + periodicity * 0.10), 4),
            )
            normalized["subghz_profile"] = "lpwan_lora_like"
            normalized["rf_subghz_profile"] = "lpwan_lora_like"
            if signal_type == "continuous" and periodicity >= 0.60:
                normalized["signal_type"] = "periodic"
            return normalized

        if (
            narrow_subghz
            and periodic_like
            and wmbus_center_aligned
            and 0.004 <= bandwidth <= 0.25
            and (
                duty_cycle <= 0.30
                or (periodicity >= 0.85 and duty_cycle >= 0.85)
            )
            and chirp_hint <= 0.35
        ):
            normalized["rf_modulation_hint"] = "FSK_like"
            normalized["rf_frame_structure"] = "metering_burst"
            normalized["rf_frame_protocol_hint"] = "WirelessMbus"
            normalized["rf_frame_confidence"] = max(
                self._safe_float(normalized.get("rf_frame_confidence"), 0.0),
                round(min(0.88, 0.40 + temporal_consistency * 0.18 + periodicity * 0.16), 4),
            )
            normalized["subghz_profile"] = "wireless_mbus_like"
            normalized["rf_subghz_profile"] = "wireless_mbus_like"
            if signal_type == "continuous" and periodicity >= 0.60:
                normalized["signal_type"] = "periodic"
            return normalized

        if not modulation_hint and not frame_structure and narrow_subghz and peak_density <= 20.0:
            normalized["rf_modulation_hint"] = "FSK_like"

        return normalized

    def _is_wireless_mbus_like(self, meta: Dict[str, Any]) -> bool:
        frame_hint = str(meta.get("rf_frame_protocol_hint") or "").strip().lower()
        frame_structure = str(meta.get("rf_frame_structure") or "").strip().lower()
        profile = str(meta.get("rf_subghz_profile") or meta.get("subghz_profile") or "").strip().lower()
        chirp = self._safe_float(meta.get("spectral_chirp_hint"), 0.0)
        modulation = str(meta.get("rf_modulation_hint") or "").strip().lower()

        if frame_hint in {"wirelessmbus", "wireless_mbus", "wmbus"} and chirp <= 0.35:
            return True
        if profile == "wireless_mbus_like" and frame_structure == "metering_burst" and chirp <= 0.35:
            return True
        if profile == "wireless_mbus_like" and modulation in {"fsk_like", "gfsk_fsk_like", "ook_fsk_like"} and chirp <= 0.15:
            return True
        return False

    def _infer_channel_family(self, protocol, band, wifi_channel, zigbee_channel, ble_channel):
        if protocol == "WIFI" or "wifi" in band:
            return "wifi"
        if protocol in {"IEEE_802.15.4_ZIGBEE", "IEEE_802.15.4", "ZIGBEE"} or "zigbee" in band:
            return "zigbee"
        if protocol == "BLE" or "ble" in band:
            return "ble"
        if ble_channel is not None:
            return "ble"
        if zigbee_channel is not None:
            return "zigbee"
        if wifi_channel is not None:
            return "wifi"
        return None

    def _estimate_channel_confidence(self, freq, family):
        if family == "wifi":
            nearest = self._nearest_wifi_center(freq)
            if nearest is None:
                return 0.0
            return round(max(0.0, 1.0 - (abs(freq - nearest) / self.WIFI_TOLERANCE_MHZ)), 3)
        if family == "zigbee":
            nearest = self._nearest_zigbee_center(freq)
            if nearest is None:
                return 0.0
            return round(max(0.0, 1.0 - (abs(freq - nearest) / self.ZIGBEE_TOLERANCE_MHZ)), 3)
        if family == "ble":
            return 1.0 if self._infer_ble_channel(freq) is not None else 0.0
        return 0.0

    def _compute_burst_recurrence_score(self, burst_ratio, periodicity, temporal_consistency, updates):
        ratio = self._safe_float(burst_ratio, 0.0)
        periodic = self._safe_float(periodicity, 0.0)
        temporal = self._safe_float(temporal_consistency, 0.0)
        persistence = min(1.0, self._safe_float(updates, 1.0) / 10.0)
        periodic_component = 1.0 if periodic > 0 else 0.0
        return round(min(1.0, (ratio * 0.35) + (periodic_component * 0.25) + (temporal * 0.25) + (persistence * 0.15)), 4)

    def _infer_lora_role(self, meta: Dict[str, Any]):
        power = self._safe_float(meta.get("power_db"), self._safe_float(meta.get("rf_power_db"), -120.0))
        hit_count = self._safe_float(meta.get("hit_count"), self._safe_float(meta.get("rf_emitter_hits"), 0.0))
        periodicity = self._safe_float(meta.get("periodicity", meta.get("rf_burst_periodicity")), 0.0)
        bandwidth_class = str(meta.get("bandwidth_class") or "").lower()
        signal_type = str(meta.get("signal_type") or "").lower()

        if hit_count >= 6 and periodicity >= 0.5 and power >= -75:
            return "gateway", 0.72
        if "narrow" in bandwidth_class or signal_type in {"burst", "periodic"} or power < -75:
            return "end_device", 0.64
        return "unknown", 0.25

    @staticmethod
    def _coerce_channel(*values):
        for value in values:
            try:
                if value is None or value == "":
                    continue
                return int(value)
            except Exception:
                continue
        return None

    def _infer_wifi_channel(self, freq):
        channels = {
            1: 2412.0, 2: 2417.0, 3: 2422.0, 4: 2427.0, 5: 2432.0, 6: 2437.0,
            7: 2442.0, 8: 2447.0, 9: 2452.0, 10: 2457.0, 11: 2462.0, 12: 2467.0,
            13: 2472.0, 14: 2484.0,
        }
        best_channel = None
        best_dist = None
        for channel, center in channels.items():
            dist = abs(freq - center)
            if dist <= self.WIFI_TOLERANCE_MHZ and (best_dist is None or dist < best_dist):
                best_channel = channel
                best_dist = dist
        return best_channel

    def _infer_zigbee_channel(self, freq):
        best_channel = None
        best_dist = None
        for channel in range(11, 27):
            center = 2405.0 + ((channel - 11) * 5.0)
            dist = abs(freq - center)
            if dist <= self.ZIGBEE_TOLERANCE_MHZ and (best_dist is None or dist < best_dist):
                best_channel = channel
                best_dist = dist
        return best_channel

    @staticmethod
    def _infer_ble_channel(freq):
        centers = {37: 2402.0, 38: 2426.0, 39: 2480.0}
        for channel, center in centers.items():
            if abs(freq - center) <= 1.0:
                return channel
        return None

    def _nearest_wifi_center(self, freq):
        channel = self._infer_wifi_channel(freq)
        if channel is None:
            return None
        return {
            1: 2412.0, 2: 2417.0, 3: 2422.0, 4: 2427.0, 5: 2432.0, 6: 2437.0,
            7: 2442.0, 8: 2447.0, 9: 2452.0, 10: 2457.0, 11: 2462.0, 12: 2467.0,
            13: 2472.0, 14: 2484.0,
        }.get(channel)

    def _nearest_zigbee_center(self, freq):
        channel = self._infer_zigbee_channel(freq)
        if channel is None:
            return None
        return 2405.0 + ((channel - 11) * 5.0)

    def _refresh_entry_state(self, entry: Dict[str, Any], now: float):
        last_seen = self._safe_float(entry.get("last_seen"), now)
        last_seen_age = max(0.0, now - last_seen)

        entry["age_sec"] = round(max(0.0, now - self._safe_float(entry.get("first_seen"), now)), 3)
        entry["last_seen_age_sec"] = round(last_seen_age, 3)

        if last_seen_age > self.STALE_TIMEOUT_SEC:
            entry["active"] = False
            entry["state"] = "stale"
        else:
            entry["active"] = True
            entry["state"] = "active"

    @staticmethod
    def _rolling_avg(old, new, updates):
        if updates <= 1:
            return float(new)
        return ((float(old) * (updates - 1)) + float(new)) / updates

    def _safe_metadata(self, meta):
        if not isinstance(meta, dict):
            return {}
        if len(meta) > self.MAX_METADATA_KEYS:
            return dict(list(meta.items())[: self.MAX_METADATA_KEYS])
        return meta

    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    # =========================================================================
    # EMITTERS
    # =========================================================================
    def get_active_emitters(self):
        with self._lock:
            now = time.time()
            self._prune_stale_signals(now)
            for s in self._signals.values():
                self._refresh_entry_state(s, now)

            signals = [copy.deepcopy(s) for s in self._signals.values() if s.get("active")]

        emitters = []

        for s in signals:
            f = self._safe_float(s.get("frequency_mhz"), None)
            if f is None:
                continue

            match = None
            for e in emitters:
                if abs(self._safe_float(e["center_freq_mhz"]) - f) <= self.EMITTER_GROUP_TOLERANCE_MHZ:
                    match = e
                    break

            if not match:
                match = {
                    "emitter_id": f"EMITTER-{f:.3f}",
                    "center_freq_mhz": f,
                    "signals": [],
                    "protocols": [],
                }
                emitters.append(match)

            match["signals"].append(s)

        for e in emitters:
            e["signal_count"] = len(e["signals"])
            e["confidence"] = (
                sum(self._safe_float(s.get("confidence"), 0.0) for s in e["signals"]) / len(e["signals"])
                if e["signals"]
                else 0.0
            )
            e["max_power"] = max(self._safe_float(s.get("power_db"), -120.0) for s in e["signals"])
            e["dominant_protocol"] = self._dominant_protocol(e["signals"])

            protos = []
            for s in e["signals"]:
                p = s.get("protocol")
                if p and p not in protos:
                    protos.append(p)
            e["protocols"] = protos

        return emitters

    def _dominant_protocol(self, signals: List[Dict[str, Any]]) -> str:
        counts: Dict[str, int] = {}
        for sig in signals:
            proto = sig.get("protocol") or "UNKNOWN_PROTOCOL"
            counts[proto] = counts.get(proto, 0) + 1
        if not counts:
            return "UNKNOWN_PROTOCOL"
        return max(counts.items(), key=lambda kv: kv[1])[0]

    # =========================================================================
    # API / STATE / SUMMARY
    # =========================================================================
    def get_all_signals(self):
        with self._lock:
            now = time.time()
            self._prune_stale_signals(now)
            for s in self._signals.values():
                self._refresh_entry_state(s, now)
            return [copy.deepcopy(s) for s in self._signals.values()]

    def list_signals(self):
        return self.get_all_signals()

    def get_signals(self):
        return self.get_all_signals()

    def get_active_signals(self):
        return [s for s in self.get_all_signals() if s.get("active")]

    def get_live_signals(self, limit=200):
        return self.get_top_signals(limit=limit, active_only=True, sort_by="last_seen")

    def get_signal(self, signal_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = time.time()
            self._prune_stale_signals(now)
            entry = self._signals.get(signal_id)
            if not entry:
                return None
            self._refresh_entry_state(entry, now)
            return copy.deepcopy(entry)

    def get_signal_by_id(self, signal_id: str) -> Optional[Dict[str, Any]]:
        return self.get_signal(signal_id)

    def get_top_signals(self, limit=10, promoted_only=False, active_only=False, sort_by="priority_score"):
        signals = self.get_all_signals()

        if active_only:
            signals = [s for s in signals if s.get("active")]
        if promoted_only:
            signals = [s for s in signals if s.get("promoted")]

        signals.sort(
            key=lambda s: self._safe_float(s.get(sort_by), -999.0),
            reverse=True,
        )
        return signals[:limit]

    def top_signals(self, limit=10, promoted_only=False, active_only=False, sort_by="priority_score"):
        return self.get_top_signals(
            limit=limit,
            promoted_only=promoted_only,
            active_only=active_only,
            sort_by=sort_by,
        )

    def get_stats(self):
        active = len(self.get_active_signals())
        return {
            "running": self._running,
            "updates_processed": self._updates_processed,
            "active_signals": active,
            "stale_timeout_sec": self.STALE_TIMEOUT_SEC,
            "prune_timeout_sec": self.PRUNE_TIMEOUT_SEC,
        }

    def get_storage_stats(self):
        return self.get_state()

    def get_state(self):
        signals = self.get_all_signals()
        active = sum(1 for s in signals if s.get("active"))
        stale = sum(1 for s in signals if s.get("state") == "stale")
        real = sum(1 for s in signals if s.get("is_real_protocol"))

        return {
            "engine_version": self.VERSION,
            "running": self._running,
            "signal_count": len(signals),
            "active_signal_count": active,
            "stale_signal_count": stale,
            "real_protocol_signal_count": real,
            "updates_processed": self._updates_processed,
            "stale_timeout_sec": self.STALE_TIMEOUT_SEC,
            "prune_timeout_sec": self.PRUNE_TIMEOUT_SEC,
        }

    def get_summary(self):
        signals = self.get_all_signals()

        protocol_counts: Dict[str, int] = {}
        band_counts: Dict[str, int] = {}
        device_type_counts: Dict[str, int] = {}
        vendor_counts: Dict[str, int] = {}

        signals_with_device_hints = 0
        real_protocol_signals = 0
        confident_real_protocol_signals = 0

        for s in signals:
            proto = s.get("protocol") or "UNKNOWN_PROTOCOL"
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            band = s.get("rf_band")
            if band:
                band_counts[str(band)] = band_counts.get(str(band), 0) + 1

            if s.get("device_id") or s.get("device_type") or s.get("device_category"):
                signals_with_device_hints += 1

            if s.get("is_real_protocol"):
                real_protocol_signals += 1
                if self._safe_float(s.get("protocol_confidence"), 0.0) >= 0.50:
                    confident_real_protocol_signals += 1

            dtype = s.get("device_type")
            if dtype:
                device_type_counts[str(dtype)] = device_type_counts.get(str(dtype), 0) + 1

            vendor = s.get("vendor")
            if vendor:
                vendor_counts[str(vendor)] = vendor_counts.get(str(vendor), 0) + 1

        return {
            "engine_version": self.VERSION,
            "signal_count": len(signals),
            "active_signal_count": sum(1 for s in signals if s.get("active")),
            "promoted_signal_count": sum(1 for s in signals if s.get("promoted")),
            "protocol_counts": protocol_counts,
            "band_counts": band_counts,
            "device_type_counts": device_type_counts,
            "vendor_counts": vendor_counts,
            "real_protocol_signals": real_protocol_signals,
            "confident_real_protocol_signals": confident_real_protocol_signals,
            "signals_with_device_hints": signals_with_device_hints,
            "emitter_count": len(self.get_active_emitters()),
        }
