# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF DEVICE INTELLIGENCE ENGINE (SIGINT-GRADE)
# FILE:         backend/recon/intelligence/device_intelligence.py
#
# VERSION:      v7.0.0 (YAML DB CONNECTED + PRODUCT/VENDOR/FINGERPRINT ACTIVE)
# UPDATED:      2026-03-24
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# SignalEngine
#     ↓
# RFDeviceFusionEngine
#     ↓
# RFDeviceIntelligenceEngine (THIS FILE)
#     ├── YAML Database Loading Layer
#     ├── Device Enrichment Layer
#     ├── Identity Resolution Layer
#     ├── Fingerprint Construction Layer
#     ├── Graph Intelligence Layer
#     ├── Behavior Modeling Layer
#     ├── RF Profile Layer
#     ├── Role Inference Layer
#     ├── Target Scoring Layer
#     └── Environment Classification Layer
#     ↓
# Intel API / Validator / Reporting / Red Team Decision Layer
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Transform fused RF devices into:
#   ✔ behavioral intelligence
#   ✔ structural intelligence
#   ✔ targeting intelligence
#   ✔ vendor / product hypotheses
#   ✔ identity-aware entities
#   ✔ fingerprint-aware entities
#
# v7 extends v6 by CONNECTING YAML databases directly into the intelligence
# engine so that vendor, product, and burst-level intelligence become part of
# the real runtime output instead of remaining placeholder-only heuristics.
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Preserve existing ecosystem / graph / behavior / role / target outputs
# ✔ Remain non-breaking for existing runtime callers
# ✔ Accept fused device objects from DeviceFusion
#
# IDENTITY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Generate stable identity-aware entities
# ✔ Promote vendor / product / fingerprint evidence into device objects
# ✔ Build identity_summary for API / validator
#
# FINGERPRINT RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Build meaningful fingerprint objects
# ✔ Score fingerprint strength
# ✔ Build fingerprint_summary for API / validator
#
# DATABASE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Auto-discover YAML DB files when available
# ✔ Load device_profiles / product_profiles / burst_signatures
# ✔ Fail safe if DB files are absent or partial
#
# RED TEAM RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Preserve role inference and target scoring
# ✔ Support prioritization of high-value RF entities
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. ZERO BREAKAGE
#    Existing outputs remain available.
#
# 2. ADDITIVE INTELLIGENCE
#    New vendor/product/fingerprint logic augments existing behavior.
#
# 3. IDENTITY-AWARE INTELLIGENCE
#    Prefer identity_id over device_id when available.
#
# 4. PROBABILISTIC INFERENCE
#    Confidence-driven, not hard-asserted certainty.
#
# 5. YAML-FIRST ENRICHMENT
#    Intelligence should come from curated DBs when available.
#
# 6. FAIL-SAFE EXECUTION
#    Missing YAML or partial data must never crash runtime.
#
# 7. OPERATOR-FIRST OUTPUT
#    Outputs should be directly usable by API, validator, and analysts.
#
# =============================================================================
# 📦 RUNTIME ATTRIBUTE SCHEMA
# =============================================================================
#
# Input device (from fusion) may contain:
#   device_id
#   identity_id
#   protocols
#   frequencies
#   rf_bands
#   confidence
#   hit_count
#   avg_power_db
#   power_db
#   bandwidth_mhz
#   burst_interval
#   burst_duration
#   vendor
#   product
#
# Output device (enriched here) may additionally contain:
#   vendor
#   product
#   identity_id
#   identity_confidence
#   identity_status
#   fingerprint
#   fingerprint_confidence
#   fingerprint_strength
#   matched_device_profile
#   matched_product_profile
#   matched_burst_signature
#
# analyze_ecosystem(...) output:
# {
#   ecosystems,
#   graph_metrics,
#   device_behaviors,
#   rf_profiles,
#   device_roles,
#   high_value_targets,
#   environment_type,
#   identity_summary,
#   fingerprint_summary
# }
#
# =============================================================================
# 🔄 CHANGE LOG
# =============================================================================
#
# v7.0.0
# ✔ Connected YAML DB loading directly into engine
# ✔ Added DB-backed vendor/product matching
# ✔ Added DB-backed burst signature matching
# ✔ Added stable identity generation when evidence exists
# ✔ Added real fingerprint object construction
# ✔ Added compatibility helpers:
#     - enrich_devices()
#     - analyze_devices()
#     - process_devices()
#     - classify_devices()
#     - get_summary()
#     - state()
# ✔ Preserved all existing graph / behavior / target functionality
#
# v6.0.0
# ✔ Added heuristic vendor/product/fingerprint activation
#
# v5.0.0
# ✔ Added identity-aware aggregation and fingerprint summary hooks
#
# =============================================================================
# 🧠 IMPORTANT NOTES
# =============================================================================
#
# - This file is an intelligence layer, not a packet decoder.
# - Vendor/product matches are hypotheses, not guaranteed ground truth.
# - Phase 4 improvement depends on this file returning identity/fingerprint
#   evidence AND the API exposing that evidence.
# - This engine intentionally degrades gracefully when YAML DBs are missing.
#
# =============================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
import hashlib
import math
import os

try:
    import yaml
except Exception:
    yaml = None


class RFDeviceIntelligenceEngine:
    VERSION = "7.0.0"

    # -------------------------------------------------------------------------
    # Matching defaults
    # -------------------------------------------------------------------------
    DEFAULT_MATCHING_WEIGHTS = {
        "protocol_family": 0.30,
        "frequency_band": 0.20,
        "modulation": 0.15,
        "burst_interval": 0.15,
        "burst_duration": 0.10,
        "role_hint": 0.05,
        "power_profile": 0.05,
    }

    DEFAULT_THRESHOLDS = {
        "device_score_threshold": 0.45,
        "product_score_threshold": 0.55,
        "burst_score_threshold": 0.45,
        "identity_score_threshold": 0.50,
        "fingerprint_score_threshold": 0.40,
    }

    # =========================================================================
    # INIT
    # =========================================================================
    def __init__(
        self,
        device_db_path: Optional[str] = None,
        rf_burst_db_path: Optional[str] = None,
        auto_load: bool = True,
    ):
        self.vendor_aliases = {
            "xiaomi": ["xiaomi", "mi", "aqara"],
            "philips": ["philips", "hue"],
            "amazon": ["amazon", "ring", "blink"],
            "google": ["google", "nest"],
            "apple": ["apple", "airtag"],
            "samsung": ["samsung", "smartthings"],
        }

        self.matching_weights: Dict[str, float] = dict(self.DEFAULT_MATCHING_WEIGHTS)
        self.confidence_thresholds: Dict[str, float] = dict(self.DEFAULT_THRESHOLDS)

        self.device_profiles: List[Dict[str, Any]] = []
        self.product_profiles: List[Dict[str, Any]] = []
        self.burst_signatures: List[Dict[str, Any]] = []
        self.rf_burst_signatures: List[Dict[str, Any]] = []

        self._db_status: Dict[str, Any] = {
            "yaml_available": yaml is not None,
            "device_db_loaded": False,
            "rf_burst_db_loaded": False,
            "device_db_path": None,
            "rf_burst_db_path": None,
            "device_profile_count": 0,
            "product_profile_count": 0,
            "burst_signature_count": 0,
            "rf_burst_signature_count": 0,
        }

        if auto_load:
            self._auto_load_databases(device_db_path, rf_burst_db_path)

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def analyze_ecosystem(self, devices: List[Dict], edges: List[Dict]) -> Dict[str, Any]:
        if not isinstance(devices, list):
            devices = []
        if not isinstance(edges, list):
            edges = []

        # v7 enrichment is additive and in-place, preserving caller expectations
        self._enrich_devices(devices)

        clusters = self._build_clusters(devices, edges)
        graph_metrics = self._compute_graph_metrics(devices, edges)
        behaviors = self._analyze_behavior(devices)
        rf_profiles = self._rf_fingerprint(devices)
        roles = self._infer_roles(devices, graph_metrics, behaviors)
        targets = self._score_targets(devices, roles, graph_metrics, behaviors, rf_profiles)
        environment = self._classify_environment(devices, roles, behaviors)

        identity_summary = self._build_identity_summary(devices)
        fingerprint_summary = self._build_fingerprint_summary(devices, rf_profiles)

        return {
            "ecosystems": clusters,
            "graph_metrics": graph_metrics,
            "device_behaviors": behaviors,
            "rf_profiles": rf_profiles,
            "device_roles": roles,
            "high_value_targets": targets,
            "environment_type": environment,
            "identity_summary": identity_summary,
            "fingerprint_summary": fingerprint_summary,
        }

    # =========================================================================
    # COMPATIBILITY HELPERS
    # =========================================================================
    def enrich_devices(self, devices: List[Dict]) -> List[Dict]:
        self._enrich_devices(devices if isinstance(devices, list) else [])
        return devices if isinstance(devices, list) else []

    def analyze_devices(self, devices: List[Dict]) -> List[Dict]:
        return self.enrich_devices(devices)

    def process_devices(self, devices: List[Dict]) -> List[Dict]:
        return self.enrich_devices(devices)

    def classify_devices(self, devices: List[Dict]) -> List[Dict]:
        return self.enrich_devices(devices)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "engine_version": self.VERSION,
            "db_status": self.state(),
        }

    def state(self) -> Dict[str, Any]:
        return {
            "engine_version": self.VERSION,
            **self._db_status,
        }

    # =========================================================================
    # YAML DATABASE LOADING
    # =========================================================================
    def _auto_load_databases(
        self,
        device_db_path: Optional[str] = None,
        rf_burst_db_path: Optional[str] = None,
    ) -> None:
        if yaml is None:
            return

        root = Path(__file__).resolve().parents[2]  # backend/

        device_candidates = [
            device_db_path,
            os.getenv("GHOSTRECON_DEVICE_DB"),
            str(root / "config" / "device_intelligence_db.yaml"),
            str(root / "config" / "protocol_device_profiles.yaml"),
            str(root / "config" / "device_profiles.yaml"),
            str(root / "config" / "product_profiles.yaml"),
        ]

        rf_burst_candidates = [
            rf_burst_db_path,
            os.getenv("GHOSTRECON_RF_BURST_DB"),
            str(root / "config" / "rf_burst_signatures.yaml"),
            str(root / "config" / "burst_signatures.yaml"),
            str(root / "recon" / "fingerprinting" / "rf_burst_signatures.yaml"),
        ]

        device_db_loaded = self._load_first_device_db(device_candidates)
        rf_burst_loaded = self._load_first_rf_burst_db(rf_burst_candidates)

        # If the main DB already carried burst_signatures, that's still useful.
        self._db_status["device_db_loaded"] = device_db_loaded
        self._db_status["rf_burst_db_loaded"] = rf_burst_loaded

    def _load_first_device_db(self, candidates: List[Optional[str]]) -> bool:
        for candidate in candidates:
            if not candidate:
                continue
            data = self._load_yaml_file(candidate)
            if isinstance(data, dict):
                self._ingest_device_db(data, candidate)
                return True
        return False

    def _load_first_rf_burst_db(self, candidates: List[Optional[str]]) -> bool:
        for candidate in candidates:
            if not candidate:
                continue
            data = self._load_yaml_file(candidate)
            if isinstance(data, dict) or isinstance(data, list):
                self._ingest_rf_burst_db(data, candidate)
                return True
        return False

    def _load_yaml_file(self, path_str: str) -> Optional[Any]:
        if yaml is None:
            return None
        try:
            path = Path(path_str).expanduser().resolve()
            if not path.exists() or not path.is_file():
                return None
            with path.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return None

    def _ingest_device_db(self, data: Dict[str, Any], source_path: str) -> None:
        self._db_status["device_db_path"] = source_path

        normalization = data.get("normalization", {})
        aliases = normalization.get("vendor_aliases", {})
        if isinstance(aliases, dict):
            for canonical, values in aliases.items():
                if isinstance(values, list):
                    self.vendor_aliases[str(canonical).lower()] = [str(v).lower() for v in values]

        weights = data.get("matching_weights", {})
        if isinstance(weights, dict):
            for key, value in weights.items():
                try:
                    self.matching_weights[str(key)] = float(value)
                except Exception:
                    continue

        thresholds = data.get("confidence_thresholds", {})
        if isinstance(thresholds, dict):
            for key, value in thresholds.items():
                try:
                    self.confidence_thresholds[str(key)] = float(value)
                except Exception:
                    continue

        if isinstance(data.get("device_profiles"), list):
            self.device_profiles = [d for d in data["device_profiles"] if isinstance(d, dict)]

        if isinstance(data.get("product_profiles"), list):
            self.product_profiles = [d for d in data["product_profiles"] if isinstance(d, dict)]

        if isinstance(data.get("burst_signatures"), list):
            self.burst_signatures = [d for d in data["burst_signatures"] if isinstance(d, dict)]

        self._db_status["device_profile_count"] = len(self.device_profiles)
        self._db_status["product_profile_count"] = len(self.product_profiles)
        self._db_status["burst_signature_count"] = len(self.burst_signatures)

    def _ingest_rf_burst_db(self, data: Any, source_path: str) -> None:
        self._db_status["rf_burst_db_path"] = source_path

        entries: List[Dict[str, Any]] = []

        if isinstance(data, dict):
            for key in ["rf_burst_signatures", "burst_signatures", "signatures", "profiles"]:
                value = data.get(key)
                if isinstance(value, list):
                    entries = [d for d in value if isinstance(d, dict)]
                    break
        elif isinstance(data, list):
            entries = [d for d in data if isinstance(d, dict)]

        self.rf_burst_signatures = entries
        self._db_status["rf_burst_signature_count"] = len(self.rf_burst_signatures)

    # =========================================================================
    # DEVICE ENRICHMENT (DB-BACKED + NON-BREAKING)
    # =========================================================================
    def _enrich_devices(self, devices: List[Dict[str, Any]]) -> None:
        for d in devices:
            if not isinstance(d, dict):
                continue

            protocols = [str(p).lower() for p in d.get("protocols", []) if p is not None]
            frequencies = self._normalize_frequency_list(d.get("frequencies", []))
            rf_bands = [str(b).lower() for b in d.get("rf_bands", []) if b is not None]

            # Preserve existing heuristics from v6
            d["vendor"] = self._normalize_vendor(d.get("vendor"))

            interval = self._safe_float(d.get("burst_interval"), None)
            duration = self._safe_float(d.get("burst_duration"), None)

            if "ble" in protocols and interval and 1000 < interval < 4000:
                d["product"] = d.get("product") or "BLE Tracker-like Device"

            if "zigbee" in protocols and duration and duration < 10:
                d["product"] = d.get("product") or "Zigbee Sensor"

            if "lora" in protocols and interval and interval > 10000:
                d["product"] = d.get("product") or "LoRa Telemetry Device"

            # DB-backed matches
            device_match, device_score = self._match_device_profile(d)
            product_match, product_score = self._match_product_profile(d)
            burst_match, burst_score = self._match_burst_signature(d)

            matched_vendor = (
                self._normalize_vendor(
                    self._first_non_null(
                        d.get("vendor"),
                        self._extract_vendor(device_match),
                        self._extract_vendor(product_match),
                        self._extract_vendor(burst_match),
                    )
                )
            )

            matched_product = self._first_non_null(
                d.get("product"),
                self._extract_product_name(product_match),
                self._extract_product_name(burst_match),
            )

            matched_device_type = self._first_non_null(
                d.get("device_type"),
                self._extract_device_name(device_match),
                self._extract_device_name(product_match),
            )

            if matched_vendor:
                d["vendor"] = matched_vendor
            if matched_product:
                d["product"] = matched_product
            if matched_device_type:
                d["device_type"] = matched_device_type

            identity_confidence = max(
                self._safe_float(d.get("identity_confidence"), 0.0),
                device_score,
                product_score,
                burst_score,
            )

            fingerprint = self._build_device_fingerprint(
                d,
                device_match=device_match,
                product_match=product_match,
                burst_match=burst_match,
                device_score=device_score,
                product_score=product_score,
                burst_score=burst_score,
            )

            fingerprint_confidence = self._safe_float(
                fingerprint.get("confidence"),
                0.0,
            )

            identity_present = bool(
                d.get("identity_id")
                or d.get("vendor")
                or d.get("product")
                or fingerprint
            )

            if identity_present and not d.get("identity_id"):
                d["identity_id"] = self._generate_identity_id(
                    device=d,
                    vendor=matched_vendor,
                    product=matched_product,
                    protocols=protocols,
                    frequencies=frequencies,
                )

            d["identity_confidence"] = identity_confidence
            d["fingerprint"] = fingerprint
            d["fingerprint_confidence"] = fingerprint_confidence
            d["fingerprint_strength"] = self._strength_label(
                max(identity_confidence, fingerprint_confidence)
            )

            if identity_present:
                if matched_product:
                    d["identity_status"] = "product_identified"
                elif matched_vendor or matched_device_type:
                    d["identity_status"] = "device_identified"
                elif fingerprint:
                    d["identity_status"] = "fingerprint_identified"
                else:
                    d["identity_status"] = d.get("identity_status", "identified")
                d["confidence"] = min(
                    1.0,
                    max(self._safe_float(d.get("confidence"), 0.0), identity_confidence),
                )
            else:
                d["identity_status"] = d.get("identity_status", "unknown")

            if device_match:
                d["matched_device_profile"] = self._profile_name(device_match)
            if product_match:
                d["matched_product_profile"] = self._profile_name(product_match)
            if burst_match:
                d["matched_burst_signature"] = self._profile_name(burst_match)

            # Keep commonly-consumed fields directly on the device for API/runtime
            if matched_product and not d.get("device_category"):
                d["device_category"] = self._category_from_protocols(protocols, rf_bands)

    # =========================================================================
    # MATCHING HELPERS
    # =========================================================================
    def _match_device_profile(self, device: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], float]:
        best = None
        best_score = 0.0

        for profile in self.device_profiles:
            score = self._score_profile_match(device, profile)
            if score > best_score:
                best = profile
                best_score = score

        if best_score < self.confidence_thresholds["device_score_threshold"]:
            return None, 0.0
        return best, round(best_score, 3)

    def _match_product_profile(self, device: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], float]:
        best = None
        best_score = 0.0

        for profile in self.product_profiles:
            score = self._score_profile_match(device, profile, product_mode=True)
            if score > best_score:
                best = profile
                best_score = score

        if best_score < self.confidence_thresholds["product_score_threshold"]:
            return None, 0.0
        return best, round(best_score, 3)

    def _match_burst_signature(self, device: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], float]:
        signatures = list(self.burst_signatures) + list(self.rf_burst_signatures)

        best = None
        best_score = 0.0

        for sig in signatures:
            score = self._score_burst_match(device, sig)
            if score > best_score:
                best = sig
                best_score = score

        if best_score < self.confidence_thresholds["burst_score_threshold"]:
            return None, 0.0
        return best, round(best_score, 3)

    def _score_profile_match(
        self,
        device: Dict[str, Any],
        profile: Dict[str, Any],
        product_mode: bool = False,
    ) -> float:
        score = 0.0
        weights = self.matching_weights

        device_protocols = {str(p).lower() for p in device.get("protocols", []) if p is not None}
        profile_protocols = self._extract_protocols(profile)

        if device_protocols and profile_protocols and device_protocols.intersection(profile_protocols):
            score += weights.get("protocol_family", 0.30)

        if self._frequency_matches(device, profile):
            score += weights.get("frequency_band", 0.20)

        if self._modulation_matches(device, profile):
            score += weights.get("modulation", 0.15)

        if self._interval_matches(device, profile):
            score += weights.get("burst_interval", 0.15)

        if self._duration_matches(device, profile):
            score += weights.get("burst_duration", 0.10)

        if self._role_hint_matches(device, profile):
            score += weights.get("role_hint", 0.05)

        if self._power_profile_matches(device, profile):
            score += weights.get("power_profile", 0.05)

        if product_mode and profile.get("vendor") and self._normalize_vendor(device.get("vendor")) == self._normalize_vendor(profile.get("vendor")):
            score += 0.05

        return min(1.0, score)

    def _score_burst_match(self, device: Dict[str, Any], sig: Dict[str, Any]) -> float:
        score = 0.0
        device_protocols = {str(p).lower() for p in device.get("protocols", []) if p is not None}
        sig_protocols = self._extract_protocols(sig)

        if device_protocols and sig_protocols and device_protocols.intersection(sig_protocols):
            score += 0.30

        if self._frequency_matches(device, sig):
            score += 0.25

        if self._interval_matches(device, sig):
            score += 0.25

        if self._duration_matches(device, sig):
            score += 0.20

        return min(1.0, score)

    # =========================================================================
    # FINGERPRINT CONSTRUCTION
    # =========================================================================
    def _build_device_fingerprint(
        self,
        device: Dict[str, Any],
        device_match: Optional[Dict[str, Any]],
        product_match: Optional[Dict[str, Any]],
        burst_match: Optional[Dict[str, Any]],
        device_score: float,
        product_score: float,
        burst_score: float,
    ) -> Dict[str, Any]:
        base = {
            "protocols": list(device.get("protocols", [])),
            "frequencies": self._normalize_frequency_list(device.get("frequencies", [])),
            "rf_bands": list(device.get("rf_bands", [])),
            "matched_device_profile": self._profile_name(device_match),
            "matched_product_profile": self._profile_name(product_match),
            "matched_burst_signature": self._profile_name(burst_match),
            "vendor": self._normalize_vendor(
                self._first_non_null(
                    device.get("vendor"),
                    self._extract_vendor(product_match),
                    self._extract_vendor(device_match),
                    self._extract_vendor(burst_match),
                )
            ),
            "product": self._first_non_null(
                device.get("product"),
                self._extract_product_name(product_match),
                self._extract_product_name(burst_match),
            ),
        }

        confidence = max(
            self._safe_float(device.get("fingerprint_confidence"), 0.0),
            device_score * 0.50 + product_score * 0.80 + burst_score * 0.70,
        )
        confidence = min(1.0, confidence)

        digest_source = "|".join(
            [
                str(base.get("vendor")),
                str(base.get("product")),
                ",".join(sorted(str(p) for p in base.get("protocols", []))),
                ",".join(sorted(str(f) for f in base.get("frequencies", []))),
                ",".join(sorted(str(b) for b in base.get("rf_bands", []))),
                str(base.get("matched_device_profile")),
                str(base.get("matched_product_profile")),
                str(base.get("matched_burst_signature")),
            ]
        )
        fingerprint_id = hashlib.sha1(digest_source.encode("utf-8")).hexdigest()[:16]

        return {
            "fingerprint_id": fingerprint_id,
            "type": "yaml_db_enriched_rf_fingerprint",
            "confidence": round(confidence, 3),
            "fingerprint_strength": self._strength_label(confidence),
            **base,
        }

    # =========================================================================
    # IDENTITY SUMMARY
    # =========================================================================
    def _build_identity_summary(self, devices: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        summary = {}

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if not key:
                continue

            identity_present = bool(
                d.get("identity_id")
                or d.get("vendor")
                or d.get("product")
                or d.get("fingerprint")
            )

            summary[key] = {
                "identity_present": identity_present,
                "identity_confidence": self._safe_float(
                    d.get("identity_confidence", d.get("confidence")),
                    0.0,
                ),
                "vendor": d.get("vendor"),
                "device_type": d.get("device_type"),
                "product": d.get("product"),
                "identity_status": d.get("identity_status", "unknown"),
                "protocols": d.get("protocols", []),
            }

        return summary

    # =========================================================================
    # FINGERPRINT SUMMARY
    # =========================================================================
    def _build_fingerprint_summary(
        self,
        devices: List[Dict[str, Any]],
        rf_profiles: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        fingerprints = {}

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if not key:
                continue

            proto_count = len(d.get("protocols", []))
            freq_count = len(d.get("frequencies", []))
            confidence = max(
                self._safe_float(d.get("confidence"), 0.0),
                self._safe_float(d.get("fingerprint_confidence"), 0.0),
            )

            fp = d.get("fingerprint")
            if not isinstance(fp, dict):
                fp = {}

            fingerprints[key] = {
                "rf_profile": rf_profiles.get(key, {}),
                "protocol_diversity": proto_count,
                "frequency_diversity": freq_count,
                "fingerprint_strength": self._strength_label(confidence),
                "product_hint": d.get("product"),
                "behavior_hint": "complex_device" if proto_count >= 2 else "simple_device",
                "fingerprint": fp,
            }

        return fingerprints

    # =========================================================================
    # VENDOR NORMALIZATION
    # =========================================================================
    def _normalize_vendor(self, vendor: Any) -> Optional[str]:
        if not vendor:
            return None

        v = str(vendor).strip().lower()
        for canonical, aliases in self.vendor_aliases.items():
            if v == canonical or v in aliases:
                return canonical
        return v

    # =========================================================================
    # CLUSTERING
    # =========================================================================
    def _build_clusters(self, devices: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        visited = set()
        clusters = []
        adjacency: Dict[str, List[str]] = {}

        for d in devices:
            if not isinstance(d, dict):
                continue
            node = d.get("identity_id") or d.get("device_id")
            if node:
                adjacency[node] = []

        for e in edges:
            if not isinstance(e, dict):
                continue
            a = e.get("device_a")
            b = e.get("device_b")
            if a in adjacency and b in adjacency:
                adjacency[a].append(b)
                adjacency[b].append(a)

        for node in adjacency:
            if node in visited:
                continue

            stack = [node]
            cluster_nodes = []

            while stack:
                current = stack.pop()

                if current in visited:
                    continue

                visited.add(current)
                cluster_nodes.append(current)

                for n in adjacency.get(current, []):
                    if n not in visited:
                        stack.append(n)

            clusters.append(
                {
                    "cluster_id": f"cluster_{len(clusters) + 1}",
                    "nodes": cluster_nodes,
                    "size": len(cluster_nodes),
                    "type": self._classify_cluster(cluster_nodes, devices),
                }
            )

        return clusters

    # =========================================================================
    # GRAPH METRICS
    # =========================================================================
    def _compute_graph_metrics(self, devices: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        metrics: Dict[str, Dict[str, Any]] = {}
        total_edges = max(1, len(edges))

        connection_count: Dict[str, int] = {}

        for d in devices:
            if not isinstance(d, dict):
                continue
            key = d.get("identity_id") or d.get("device_id")
            if key:
                connection_count[key] = 0

        for e in edges:
            if not isinstance(e, dict):
                continue
            a = e.get("device_a")
            b = e.get("device_b")
            if a in connection_count:
                connection_count[a] += 1
            if b in connection_count:
                connection_count[b] += 1

        for key, degree in connection_count.items():
            centrality = degree / total_edges
            metrics[key] = {
                "degree": degree,
                "centrality": round(centrality, 3),
                "connectivity_class": (
                    "high" if degree >= 3 else "medium" if degree >= 2 else "low"
                ),
            }

        return metrics

    # =========================================================================
    # BEHAVIOR
    # =========================================================================
    def _analyze_behavior(self, devices: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        behaviors = {}

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if not key:
                continue

            hit_count = self._safe_int(d.get("hit_count"), 1)
            avg_power = self._safe_float(d.get("avg_power_db", d.get("power_db")), -80.0)

            activity_level = min(1.0, hit_count / 20.0)

            if activity_level > 0.7:
                pattern = "continuous"
            elif activity_level > 0.3:
                pattern = "bursty"
            else:
                pattern = "sporadic"

            behaviors[key] = {
                "activity_level": round(activity_level, 3),
                "pattern": pattern,
                "power_profile": "strong" if avg_power > -50 else "weak",
            }

        return behaviors

    # =========================================================================
    # RF PROFILE
    # =========================================================================
    def _rf_fingerprint(self, devices: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        profiles = {}

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if not key:
                continue

            power = self._safe_float(d.get("power_db"), -80.0)
            bandwidth = self._safe_float(d.get("bandwidth_mhz"), 0.2)

            profiles[key] = {
                "power_class": "high" if power > -40 else "medium" if power > -70 else "low",
                "bandwidth_class": "wideband" if bandwidth > 5 else "narrowband",
            }

        return profiles

    # =========================================================================
    # ROLE INFERENCE
    # =========================================================================
    def _infer_roles(
        self,
        devices: List[Dict[str, Any]],
        graph: Dict[str, Dict[str, Any]],
        behavior: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        roles = {}

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if not key:
                continue

            degree = graph.get(key, {}).get("degree", 0)
            activity = behavior.get(key, {}).get("activity_level", 0.0)
            protocols = {str(p).lower() for p in d.get("protocols", []) if p is not None}

            score_hub = min(1.0, degree / 5.0) + activity * 0.5
            score_device = 0.0

            if "wifi" in protocols and "ble" in protocols:
                score_device += 0.7
            if "zigbee" in protocols:
                score_device += 0.6

            if score_hub > score_device:
                role = "hub/controller"
                confidence = score_hub
            else:
                role = "endpoint"
                confidence = score_device

            roles[key] = {
                "role": role,
                "confidence": round(min(1.0, confidence), 3),
                "evidence": {
                    "degree": degree,
                    "activity": activity,
                    "protocols": list(protocols),
                },
            }

        return roles

    # =========================================================================
    # TARGET SCORING
    # =========================================================================
    def _score_targets(
        self,
        devices: List[Dict[str, Any]],
        roles: Dict[str, Dict[str, Any]],
        graph: Dict[str, Dict[str, Any]],
        behavior: Dict[str, Dict[str, Any]],
        rf: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        targets = []

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if not key:
                continue

            centrality = self._safe_float(graph.get(key, {}).get("centrality"), 0.0)
            activity = self._safe_float(behavior.get(key, {}).get("activity_level"), 0.0)

            protocols = d.get("protocols", [])
            protocol_diversity = len(protocols) / 5.0

            power_class = rf.get(key, {}).get("power_class")
            power_score = 1.0 if power_class == "high" else 0.5 if power_class == "medium" else 0.2

            score = (
                centrality * 0.4
                + protocol_diversity * 0.2
                + activity * 0.2
                + power_score * 0.2
            )

            if score > 0.6:
                targets.append(
                    {
                        "identity_id": key,
                        "score": round(score, 3),
                        "priority": "critical" if score > 0.85 else "high" if score > 0.7 else "medium",
                        "attack_surface": protocols,
                    }
                )

        targets.sort(key=lambda x: x["score"], reverse=True)
        return targets

    # =========================================================================
    # ENVIRONMENT
    # =========================================================================
    def _classify_environment(
        self,
        devices: List[Dict[str, Any]],
        roles: Dict[str, Dict[str, Any]],
        behavior: Dict[str, Dict[str, Any]],
    ) -> str:
        hubs = sum(1 for r in roles.values() if r.get("role") == "hub/controller")
        sensors = sum(
            1
            for d in devices
            if isinstance(d, dict) and "zigbee" in [str(p).lower() for p in d.get("protocols", [])]
        )
        high_activity = sum(1 for b in behavior.values() if self._safe_float(b.get("activity_level"), 0.0) > 0.6)

        if hubs >= 1 and sensors >= 2:
            return "smart_home"
        if high_activity >= 5:
            return "office"
        return "unknown"

    # =========================================================================
    # CLUSTER TYPE
    # =========================================================================
    def _classify_cluster(self, cluster_ids: List[str], devices: List[Dict[str, Any]]) -> str:
        protos = set()

        for d in devices:
            if not isinstance(d, dict):
                continue

            key = d.get("identity_id") or d.get("device_id")
            if key in cluster_ids:
                protos.update([str(p).lower() for p in d.get("protocols", []) if p is not None])

        if "zigbee" in protos and "wifi" in protos:
            return "smart_home_cluster"
        if "wifi" in protos:
            return "wifi_cluster"
        if "subghz" in protos:
            return "subghz_cluster"
        return "generic_cluster"

    # =========================================================================
    # INTERNAL UTILITIES
    # =========================================================================
    def _extract_protocols(self, profile: Dict[str, Any]) -> set:
        values = set()

        for key in ["protocol_family", "protocol", "protocols", "expected_protocols"]:
            value = profile.get(key)
            if isinstance(value, str):
                values.add(value.lower())
            elif isinstance(value, list):
                values.update(str(v).lower() for v in value if v is not None)

        return values

    def _extract_vendor(self, profile: Optional[Dict[str, Any]]) -> Optional[str]:
        if not isinstance(profile, dict):
            return None
        for key in ["vendor", "manufacturer", "brand"]:
            if profile.get(key):
                return str(profile.get(key))
        return None

    def _extract_product_name(self, profile: Optional[Dict[str, Any]]) -> Optional[str]:
        if not isinstance(profile, dict):
            return None
        for key in ["product_name", "product", "device", "name", "signature_name"]:
            if profile.get(key):
                return str(profile.get(key))
        return None

    def _extract_device_name(self, profile: Optional[Dict[str, Any]]) -> Optional[str]:
        if not isinstance(profile, dict):
            return None
        for key in ["device", "device_type", "name", "class"]:
            if profile.get(key):
                return str(profile.get(key))
        return None

    def _profile_name(self, profile: Optional[Dict[str, Any]]) -> Optional[str]:
        return self._extract_product_name(profile)

    def _frequency_matches(self, device: Dict[str, Any], profile: Dict[str, Any]) -> bool:
        device_freqs = self._normalize_frequency_list(device.get("frequencies", []))
        if not device_freqs:
            return False

        candidates = []
        for key in ["expected_band_mhz", "band_mhz", "frequency_range_mhz", "frequencies"]:
            value = profile.get(key)
            if value is not None:
                candidates.append(value)

        for freq in device_freqs:
            for value in candidates:
                if self._value_matches_range(freq, value):
                    return True
        return False

    def _modulation_matches(self, device: Dict[str, Any], profile: Dict[str, Any]) -> bool:
        device_mods = set()
        for key in ["modulation", "modulations", "modulation_types"]:
            value = device.get(key)
            if isinstance(value, str):
                device_mods.add(value.lower())
            elif isinstance(value, list):
                device_mods.update(str(v).lower() for v in value if v is not None)

        profile_mods = set()
        for key in ["modulation", "modulations", "modulation_types"]:
            value = profile.get(key)
            if isinstance(value, str):
                profile_mods.add(value.lower())
            elif isinstance(value, list):
                profile_mods.update(str(v).lower() for v in value if v is not None)

        return bool(device_mods and profile_mods and device_mods.intersection(profile_mods))

    def _interval_matches(self, device: Dict[str, Any], profile: Dict[str, Any]) -> bool:
        interval = self._safe_float(device.get("burst_interval"), None)
        if interval is None:
            interval = self._safe_float(device.get("periodicity_ms"), None)
        if interval is None:
            return False

        for key in ["burst_interval_ms", "periodicity_ms", "interval_ms"]:
            value = profile.get(key)
            if value is not None and self._value_matches_range(interval, value):
                return True
        return False

    def _duration_matches(self, device: Dict[str, Any], profile: Dict[str, Any]) -> bool:
        duration = self._safe_float(device.get("burst_duration"), None)
        if duration is None:
            duration = self._safe_float(device.get("duration_ms"), None)
        if duration is None:
            return False

        for key in ["burst_duration_ms", "duration_ms", "burst_ms"]:
            value = profile.get(key)
            if value is not None and self._value_matches_range(duration, value):
                return True
        return False

    def _role_hint_matches(self, device: Dict[str, Any], profile: Dict[str, Any]) -> bool:
        device_role = self._first_non_null(device.get("device_role_hint"), device.get("device_type"))
        profile_role = self._first_non_null(profile.get("role"), profile.get("device_type"))
        if not device_role or not profile_role:
            return False
        return str(device_role).lower() == str(profile_role).lower()

    def _power_profile_matches(self, device: Dict[str, Any], profile: Dict[str, Any]) -> bool:
        power = self._safe_float(device.get("avg_power_db", device.get("power_db")), None)
        if power is None:
            return False

        value = profile.get("power_db_range")
        return self._value_matches_range(power, value)

    def _value_matches_range(self, value: float, spec: Any) -> bool:
        if spec is None:
            return False

        if isinstance(spec, (int, float)):
            return abs(value - float(spec)) <= max(1.0, abs(float(spec)) * 0.10)

        if isinstance(spec, list):
            if len(spec) == 2 and all(isinstance(v, (int, float)) for v in spec):
                low, high = float(spec[0]), float(spec[1])
                return low <= value <= high

            for entry in spec:
                if self._value_matches_range(value, entry):
                    return True

        if isinstance(spec, dict):
            low = self._safe_float(spec.get("min"), None)
            high = self._safe_float(spec.get("max"), None)
            if low is not None and high is not None:
                return low <= value <= high

        return False

    def _normalize_frequency_list(self, values: Any) -> List[float]:
        result = []
        if isinstance(values, (list, tuple, set)):
            for v in values:
                fv = self._safe_float(v, None)
                if fv is not None:
                    result.append(round(fv, 3))
        else:
            fv = self._safe_float(values, None)
            if fv is not None:
                result.append(round(fv, 3))
        return sorted(set(result))

    def _generate_identity_id(
        self,
        device: Dict[str, Any],
        vendor: Optional[str],
        product: Optional[str],
        protocols: List[str],
        frequencies: List[float],
    ) -> str:
        source = "|".join(
            [
                str(vendor or "unknown"),
                str(product or "unknown"),
                ",".join(sorted(protocols)),
                ",".join(str(f) for f in frequencies[:5]),
                str(device.get("device_id")),
            ]
        )
        digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:12]
        return f"ID-{digest}"

    def _strength_label(self, confidence: float) -> str:
        if confidence > 0.75:
            return "strong"
        if confidence > 0.50:
            return "medium"
        return "weak"

    def _category_from_protocols(self, protocols: List[str], rf_bands: List[str]) -> Optional[str]:
        protos = set(protocols)
        bands = set(rf_bands)

        if "zigbee" in protos:
            return "zigbee_iot"
        if "ble" in protos:
            return "ble_iot"
        if "lora" in protos:
            return "lora_telemetry"
        if "wifi" in protos:
            return "wifi_device"
        if "subghz" in protos or "subghz" in bands:
            return "subghz_device"
        return None

    @staticmethod
    def _first_non_null(*values: Any) -> Any:
        for value in values:
            if value is not None:
                return value
        return None

    @staticmethod
    def _safe_float(value: Any, default: Optional[float] = 0.0) -> Optional[float]:
        try:
            if value is None:
                return default
            result = float(value)
            if math.isnan(result) or math.isinf(result):
                return default
            return result
        except Exception:
            return default

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default
