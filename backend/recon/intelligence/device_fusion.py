# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       DEVICE FUSION ENGINE
# FILE:         backend/recon/intelligence/device_fusion.py
# VERSION:      v37.0.0 (SIGINT-GRADE - IDENTITY DETECTION FIX)
# UPDATED:      2026-03-23
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# SignalEngine
#     ↓
# RFDeviceFusionEngine (THIS FILE)
#     ├── Observation Normalization
#     ├── Device Resolution
#     ├── Evidence Accumulation
#     ├── Identity Ingestion
#     ├── Identity Binding (ROBUST - FIXED)
#     ├── Confidence Stabilization
#     └── Export (JSON SAFE)
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Convert RF emitters → persistent tracked devices
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# ✔ Normalize RF observations
# ✔ Resolve OR CREATE devices
# ✔ Maintain continuity
# ✔ Bind identity (BLE / future WiFi)
# ✔ Export safely
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. RF IS NOISY → NEVER TRUST SINGLE SIGNAL
# 2. IDENTITY MATCHING MUST BE ROBUST
# 3. PROTOCOL CLASSIFIER IS NOT TRUTH
# 4. FREQUENCY + BEHAVIOR > LABELS
# 5. NEVER BREAK PIPELINE
#
# =============================================================================
# 🔄 CHANGE LOG (v37.0.0)
# =============================================================================
#
# ✔ FIXED identity binding (protocol + frequency hybrid detection)
# ✔ REMOVED overly strict BLE-only filter
# ✔ IMPROVED robustness against classifier noise
# ✔ PRESERVED all existing functionality
#
# =============================================================================

from __future__ import annotations

import copy
import time
from typing import Any, Dict, Iterable, List, Optional


class RFDeviceFusionEngine:

    VERSION = "37.0.0"

    FREQ_MATCH_TOLERANCE_MHZ = 1.0
    MATCH_SCORE_THRESHOLD = 0.60
    IDENTITY_TTL = 30.0
    DEVICE_STALE_TIMEOUT = 45.0
    OBSERVATION_HINT_FIELDS = (
        "vendor",
        "product",
        "device_type",
        "device_category",
        "device_role_hint",
        "device_role_confidence",
        "product_category_hint",
        "product_category_confidence",
        "behavior_profile_hint",
        "rf_device_class",
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
    )

    def __init__(self, identity_tracker=None):

        self.devices: Dict[str, Dict[str, Any]] = {}
        self.device_counter = 0

        self.emitter_to_device: Dict[str, str] = {}
        self.device_edges: List[Dict[str, Any]] = []

        self.identity_tracker = identity_tracker
        self.identity_cache: Dict[str, Dict[str, Any]] = {}

    # =========================================================================
    # IDENTITY INGESTION
    # =========================================================================
    def ingest_identity(self, identity: Dict[str, Any]):

        if not isinstance(identity, dict):
            return

        device_id = identity.get("device_id")
        if not device_id:
            return

        self.identity_cache[device_id] = {
            "data": identity,
            "timestamp": time.time(),
        }

    def reset(self):
        self.devices.clear()
        self.emitter_to_device.clear()
        self.device_edges.clear()
        self.identity_cache.clear()
        self.device_counter = 0

    def _prune_stale_devices(self, now: float) -> None:
        stale_device_ids = []
        for device_id, device in self.devices.items():
            last_seen = self._safe_float(device.get("last_seen"), now)
            if (now - last_seen) > self.DEVICE_STALE_TIMEOUT:
                stale_device_ids.append(device_id)

        for device_id in stale_device_ids:
            self.devices.pop(device_id, None)

        if stale_device_ids:
            stale_set = set(stale_device_ids)
            self.emitter_to_device = {
                emitter_id: device_id
                for emitter_id, device_id in self.emitter_to_device.items()
                if device_id not in stale_set
            }
            self.device_edges = [
                edge for edge in self.device_edges
                if edge.get("source") not in stale_set and edge.get("target") not in stale_set
            ]

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def fuse(self, emitters: Optional[Iterable[Dict[str, Any]]]):

        now = time.time()
        self._cleanup_identity_cache(now)
        self._prune_stale_devices(now)

        for raw in emitters or []:

            observation = self._normalize_observation(raw, now)
            if observation is None:
                continue

            device = self._resolve_or_create(observation, now)

            self._attach(device, observation, now)
            self._bind_identity(device, observation, now)

        return self.export_graph(now)

    # =========================================================================
    # RESOLVE OR CREATE
    # =========================================================================
    def _resolve_or_create(self, observation: Dict[str, Any], now: float):

        best_device = None
        best_score = 0.0

        for device in self.devices.values():

            score = self._match_score(device, observation)

            if score > best_score:
                best_score = score
                best_device = device

        if best_device and best_score >= self.MATCH_SCORE_THRESHOLD:
            return best_device

        device_id = f"DEV-{self.device_counter}"
        self.device_counter += 1

        device = {
            "device_id": device_id,
            "frequencies": set(observation.get("frequencies", [])),
            "protocols": set(observation.get("protocols", [])),
            "rf_bands": set(observation.get("rf_bands", [])),
            "channel_family": observation.get("channel_family"),
            "confidence": observation.get("confidence", 0.3),
            "first_seen": now,
            "last_seen": now,
        }
        self._apply_observation_hints(device, observation)

        self.devices[device_id] = device
        return device

    # =========================================================================
    # MATCH SCORE
    # =========================================================================
    def _match_score(self, device: Dict[str, Any], obs: Dict[str, Any]):

        score = 0.0
        device_family = str(device.get("channel_family") or "").lower()
        obs_family = str(obs.get("channel_family") or "").lower()

        if device_family and obs_family and device_family != obs_family:
            return 0.0

        tolerance = self._match_tolerance(device_family or obs_family)

        for df in device.get("frequencies", set()):
            for of in obs.get("frequencies", set()):
                if abs(df - of) <= tolerance:
                    score += 0.5

        if device.get("protocols", set()).intersection(obs.get("protocols", set())):
            score += 0.3

        if device_family and obs_family and device_family == obs_family:
            score += 0.2

        if device.get("identity_id") and obs.get("rf_emitter_id"):
            score += 0.2

        if abs(device.get("last_seen", 0) - obs.get("last_seen", 0)) < 5:
            score += 0.1

        return score

    # =========================================================================
    # ATTACH
    # =========================================================================
    def _attach(self, device: Dict[str, Any], obs: Dict[str, Any], now: float):
        obs_protocols = self._sanitize_protocols(
            obs.get("protocols", set()),
            obs.get("channel_family"),
            obs.get("frequencies", set()),
            obs,
        )

        device["frequencies"].update(obs.get("frequencies", []))
        if obs_protocols:
            device["protocols"].update(obs_protocols)
            device["protocols"] = self._sanitize_protocols(
                device.get("protocols", set()),
                device.get("channel_family") or obs.get("channel_family"),
                device.get("frequencies", set()),
                {**device, **obs},
            )
        device["rf_bands"] = device.get("rf_bands", set()).union(obs.get("rf_bands", set()))
        device["channel_family"] = device.get("channel_family") or obs.get("channel_family")

        device["last_seen"] = now
        self._apply_observation_hints(device, obs)

        device["confidence"] = min(
            1.0,
            (device.get("confidence", 0.0) * 0.7)
            + (obs.get("confidence", 0.0) * 0.3),
        )

    # =========================================================================
    # 🔥 IDENTITY BINDING (SIGINT FIX)
    # =========================================================================
    def _bind_identity(self, device: Dict[str, Any], observation: Dict[str, Any], now: float):

        if not self.identity_cache:
            return

        protocols = observation.get("protocols", set())
        frequencies = observation.get("frequencies", set())

        # ---------------------------------------------------------
        # SIGINT-grade BLE detection (NOT classifier dependent)
        # ---------------------------------------------------------
        is_ble_like = False

        # Protocol hint (weak)
        if "BLE" in protocols:
            is_ble_like = True

        # Frequency fallback (STRONG)
        for f in frequencies:
            try:
                if 2400 <= float(f) <= 2485:
                    is_ble_like = True
                    break
            except Exception:
                continue

        if not is_ble_like:
            return

        # ---------------------------------------------------------
        # Identity binding
        # ---------------------------------------------------------
        for identity_id, entry in list(self.identity_cache.items()):

            identity = entry.get("data", {})
            ts = entry.get("timestamp", 0.0)

            if now - ts > self.IDENTITY_TTL:
                continue

            device["identity_id"] = identity.get("device_id")

            if identity.get("vendor"):
                device["vendor"] = identity.get("vendor")

            if identity.get("fingerprint"):
                existing = device.get("fingerprint") or {}
                new = identity.get("fingerprint") or {}
                device["fingerprint"] = {**existing, **new}

            incoming_conf = float(identity.get("identity_confidence", 0.0))
            device["identity_confidence"] = max(
                float(device.get("identity_confidence", 0.0)),
                incoming_conf,
            )

            device["confidence"] = min(1.0, device.get("confidence", 0.0) + 0.05)
            device["identity_last_seen"] = now

            break

    # =========================================================================
    # NORMALIZATION
    # =========================================================================
    def _normalize_observation(self, raw: Any, now: float) -> Optional[Dict[str, Any]]:

        if not isinstance(raw, dict):
            return None

        signals = raw.get("signals") if isinstance(raw.get("signals"), list) else []

        protocol = raw.get("dominant_protocol") or raw.get("rf_protocol") or raw.get("protocol")

        frequency = self._safe_float(
            raw.get("center_freq_mhz", raw.get("frequency_mhz")),
            None,
        )

        rf_band = raw.get("rf_band") or raw.get("band")
        confidence = self._safe_float(raw.get("confidence"), 0.0)
        channel_family = str(raw.get("channel_family") or "").lower() or None

        protocols = set()
        frequencies = set()
        rf_bands = set()

        if protocol:
            protocols.add(self._canonical_protocol(protocol))

        if frequency is not None:
            frequencies.add(round(float(frequency), 1))

        if rf_band:
            rf_bands.add(str(rf_band))

        for sig in signals:
            if not isinstance(sig, dict):
                continue

            if sig.get("protocol"):
                protocols.add(self._canonical_protocol(sig.get("protocol")))

            if not channel_family and sig.get("channel_family"):
                channel_family = str(sig.get("channel_family")).lower()

            freq = self._safe_float(sig.get("frequency_mhz"), None)
            if freq is not None:
                frequencies.add(round(freq, 1))

        normalized = {
            "protocols": set(protocols),
            "frequencies": frequencies,
            "rf_bands": rf_bands,
            "channel_family": channel_family,
            "confidence": confidence,
            "last_seen": now,
        }
        for field in self.OBSERVATION_HINT_FIELDS:
            value = self._first_observation_value(raw, signals, field)
            if value is not None:
                normalized[field] = copy.deepcopy(value)
        normalized["protocols"] = self._sanitize_protocols(
            normalized.get("protocols", set()),
            channel_family,
            frequencies,
            normalized,
        )
        return normalized

    # =========================================================================
    # EXPORT
    # =========================================================================
    def export_graph(self, now: float):
        self._prune_stale_devices(now)

        result = []

        for d in self.devices.values():
            d_copy = dict(d)

            d_copy["frequencies"] = list(d.get("frequencies", []))
            d_copy["protocols"] = list(d.get("protocols", []))
            d_copy["rf_bands"] = list(d.get("rf_bands", []))

            result.append(d_copy)

        return result

    def _apply_observation_hints(self, device: Dict[str, Any], obs: Dict[str, Any]) -> None:
        for field in self.OBSERVATION_HINT_FIELDS:
            value = obs.get(field)
            if value is None:
                continue

            if field == "lora_identity_evidence":
                merged = list(device.get(field) or [])
                for item in value if isinstance(value, list) else [value]:
                    if item not in merged:
                        merged.append(item)
                if merged:
                    device[field] = merged
                continue

            if isinstance(value, bool):
                device[field] = bool(device.get(field)) or value
                continue

            if isinstance(value, (int, float)):
                device[field] = max(self._safe_float(device.get(field), 0.0), float(value))
                continue

            if device.get(field) is None:
                device[field] = copy.deepcopy(value)

    def _first_observation_value(self, raw: Dict[str, Any], signals: List[Dict[str, Any]], field: str) -> Any:
        value = raw.get(field)
        if value is not None:
            return value
        for sig in signals:
            if not isinstance(sig, dict):
                continue
            value = sig.get(field)
            if value is not None:
                return value
            meta = sig.get("metadata")
            if isinstance(meta, dict) and meta.get(field) is not None:
                return meta.get(field)
        return None

    # =========================================================================
    # CLEANUP
    # =========================================================================
    def _cleanup_identity_cache(self, now: float):

        expired = [
            k for k, v in self.identity_cache.items()
            if now - v["timestamp"] > self.IDENTITY_TTL
        ]

        for k in expired:
            del self.identity_cache[k]

    def _match_tolerance(self, channel_family: str) -> float:
        if channel_family == "ble":
            return 0.8
        if channel_family == "zigbee":
            return 1.2
        if channel_family == "wifi":
            return 4.0
        return self.FREQ_MATCH_TOLERANCE_MHZ

    # =========================================================================
    # SAFE HELPERS
    # =========================================================================
    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    @staticmethod
    def _canonical_protocol(value: Any) -> str:
        label = str(value or "").strip().upper().replace("-", "_")
        mapping = {
            "BLUETOOTH_LE": "BLE",
            "IEEE_802.11": "WIFI",
            "IEEE_802.15.4": "ZIGBEE",
        }
        return mapping.get(label, label)

    def _sanitize_protocols(
        self,
        protocols: Any,
        channel_family: Optional[str],
        frequencies: Any,
        hints: Optional[Dict[str, Any]] = None,
    ) -> set[str]:
        cleaned = {
            self._canonical_protocol(proto)
            for proto in (protocols or set())
            if str(proto or "").strip()
        }

        family = str(channel_family or "").lower()
        freq_values = []
        for freq in frequencies or []:
            parsed = self._safe_float(freq, None)
            if parsed is not None:
                freq_values.append(parsed)
        hints = hints or {}

        if family == "ble":
            allowed = {"BLE", "UNKNOWN_PROTOCOL"}
            ble_like = any(2400.0 <= freq <= 2485.0 for freq in freq_values) if freq_values else True
            return {proto for proto in cleaned if proto in allowed} or ({"BLE"} if ble_like else cleaned)

        if family == "zigbee":
            allowed = {"ZIGBEE", "UNKNOWN_PROTOCOL"}
            return {proto for proto in cleaned if proto in allowed} or cleaned

        if family == "wifi":
            allowed = {"WIFI", "UNKNOWN_PROTOCOL"}
            return {proto for proto in cleaned if proto in allowed} or cleaned

        if self._is_wireless_mbus_like(hints, freq_values):
            allowed = {"WIRELESS_MBUS", "SUBGHZ_FSK", "UNKNOWN_PROTOCOL"}
            filtered = {proto for proto in cleaned if proto in allowed}
            return filtered or {"WIRELESS_MBUS"}

        if self._is_lora_like(hints, freq_values):
            allowed = {"LORA", "UNKNOWN_PROTOCOL"}
            filtered = {proto for proto in cleaned if proto in allowed}
            return filtered or {"LORA"}

        return cleaned

    def _is_wireless_mbus_like(self, hints: Dict[str, Any], freq_values: List[float]) -> bool:
        type_hint = str(hints.get("device_type") or "").strip().lower()
        if "wireless m-bus" in type_hint or "meter" in type_hint:
            return True

        role = str(hints.get("subghz_role") or "").strip().lower()
        product_hint = str(hints.get("product_category_hint") or "").strip().lower()
        if role == "meter_endpoint" or product_hint == "wireless_mbus_meter":
            return True

        profile = str(hints.get("subghz_profile") or hints.get("rf_subghz_profile") or "").strip().lower()
        frame_hint = str(hints.get("rf_frame_protocol_hint") or "").strip().lower()
        frame_structure = str(hints.get("rf_frame_structure") or "").strip().lower()
        chirp = self._safe_float(hints.get("spectral_chirp_hint"), 0.0)

        if frame_hint in {"wirelessmbus", "wireless_mbus", "wmbus"} and chirp <= 0.35:
            return True
        if profile == "wireless_mbus_like" and frame_structure == "metering_burst" and chirp <= 0.35:
            return True
        if any(abs(freq - center) <= 0.18 for freq in freq_values for center in (868.30, 868.95, 869.525)):
            return profile == "wireless_mbus_like" and chirp <= 0.15
        return False

    def _is_lora_like(self, hints: Dict[str, Any], freq_values: List[float]) -> bool:
        family = str(hints.get("lora_identity_family") or "").strip().lower()
        if family in {
            "lorawan_gateway",
            "lora_gateway",
            "utility_meter_endpoint",
            "ami_meter_endpoint",
            "meter_like_endpoint",
            "meshtastic_node",
            "industrial_lora_sensor",
            "lorawan_endpoint",
            "lora_end_device",
        }:
            return True

        type_hint = str(hints.get("lora_device_type_hint") or hints.get("device_type") or "").strip().lower()
        if "lora" in type_hint or "meshtastic" in type_hint:
            return True

        profile = str(hints.get("subghz_profile") or hints.get("rf_subghz_profile") or "").strip().lower()
        if "lora" in profile:
            return True

        modulation = str(hints.get("rf_modulation_hint") or "").strip().lower()
        frame_structure = str(hints.get("rf_frame_structure") or "").strip().lower()
        if modulation == "lora_like" or frame_structure == "chirp" or bool(hints.get("rf_chirp_detected")):
            return True

        return any(433.0 <= freq <= 435.5 or 863.0 <= freq <= 928.0 for freq in freq_values) and bool(hints.get("lora_lorawan_like"))
