# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF DEVICE BEHAVIOR INTELLIGENCE ENGINE
# FILE:         backend/recon/intelligence/device_behavior.py
#
# VERSION:      v3.0.0 (PHASE-3 PRODUCTION DEVICE BEHAVIOR UPGRADE)
# UPDATED:      2026-03-16
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is an RF reconnaissance and device intelligence platform built for
# red-team operations. The purpose of this module is to interpret temporal and
# behavioral RF evidence into conservative device-role hypotheses that are more
# operationally useful than raw timing statistics alone.
#
# This module sits between low-level behavior analysis and higher-level device
# intelligence / fusion. It does NOT identify exact products. Instead, it
# produces explainable role-level assessments such as:
#
# • beaconing device
# • telemetry sensor
# • user-triggered control device
# • high-activity network node
# • low-rate asset / tag candidate
# • event-driven endpoint
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# ReconEngine / SignalEngine
#     ↓
# RFBehaviorEngine
#     ↓
# RFDeviceBehaviorEngine   ← THIS MODULE
#     ↓
# RFDeviceIntelligenceEngine
#     ↓
# RFDeviceFusionEngine / Intel API
#
#
# INPUT MODEL
# -----------------------------------------------------------------------------
# Mixed-schema RF behavior and optional protocol/context hints, including:
#
# • rf_behavior_pattern
# • rf_behavior_subtype
# • rf_behavior_confidence
# • rf_behavior_protocol_hint / rf_protocol / protocol
# • rf_interval_avg
# • rf_interval_cv
# • rf_burst_clusters
# • rf_burst_ratio
# • rf_stability_score
# • rf_periodicity_score
# • rf_frequency_mhz / frequency_mhz / freq_mhz
#
#
# OUTPUT MODEL
# -----------------------------------------------------------------------------
# • rf_behavior_pattern
# • rf_behavior_subtype
# • rf_behavior_device_role
# • rf_behavior_device_class
# • rf_behavior_ecosystem
# • rf_behavior_confidence
# • rf_behavior_reasoning
# • rf_behavior_tags
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. ROLE-LEVEL INFERENCE, NOT PRODUCT OVERCLAIM
# -----------------------------------------------------------------------------
# This engine should infer likely device roles, not exact product identity.
#
#
# 2. EXPLAINABLE BEHAVIORAL INTELLIGENCE
# -----------------------------------------------------------------------------
# Every output should carry reasoning and supporting tags.
#
#
# 3. SAFE CONFIDENCE HANDLING
# -----------------------------------------------------------------------------
# Confidence reflects role-fit quality, not certainty of exact device identity.
#
#
# 4. MIXED-SCHEMA COMPATIBILITY
# -----------------------------------------------------------------------------
# The engine must tolerate evolving upstream modules and normalize inputs.
#
#
# 5. LIGHTWEIGHT REALTIME OPERATION
# -----------------------------------------------------------------------------
# The engine must remain efficient for continuous SDR scanning.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • interpreting temporal RF behavior into device-role hypotheses
# • mapping patterns to likely ecosystems
# • attaching reasoning and behavioral tags
# • conservative confidence fusion
#
#
# This module is NOT responsible for:
#
# • SDR control
# • packet decoding
# • modulation classification
# • exact product/vendor attribution
# • final cross-signal fusion
#
# =============================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional


class RFDeviceBehaviorEngine:
    VERSION = "3.0.0"

    CONFIDENCE_LOW = 0.35
    CONFIDENCE_MEDIUM = 0.55
    CONFIDENCE_HIGH = 0.78

    # -------------------------------------------------------------------------
    # PUBLIC API
    # -------------------------------------------------------------------------

    def analyze(self, rf_features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert temporal/behavioral RF evidence into a conservative device-role
        hypothesis.

        Returns None only when there is insufficient evidence to make even a
        low-confidence role inference.
        """
        f = self._normalize_features(rf_features or {})

        if f["interval_avg"] is None and not f["behavior_pattern"]:
            return None

        candidates = self._build_candidates(f)
        if not candidates:
            return None

        best_key = max(candidates.keys(), key=lambda k: candidates[k]["score"])
        winner = candidates[best_key]

        score = max(0.0, min(1.0, winner["score"]))

        result = {
            "rf_behavior_pattern": f["behavior_pattern"] or winner["behavior_pattern"],
            "rf_behavior_subtype": f["behavior_subtype"] or winner["behavior_subtype"],
            "rf_behavior_device_role": winner["device_role"],
            "rf_behavior_device_class": winner["device_class"],
            "rf_behavior_ecosystem": winner["ecosystem"],
            "rf_behavior_confidence": round(score, 4),
            "rf_behavior_confidence_label": self._confidence_label(score),
            "rf_behavior_reasoning": winner["reasoning"],
            "rf_behavior_tags": winner["tags"],
        }

        # Legacy compatibility fields used by older downstream modules.
        result["rf_behavior_device"] = winner["device_class"]

        return result

    # -------------------------------------------------------------------------
    # NORMALIZATION
    # -------------------------------------------------------------------------

    def _normalize_features(self, rf_features: Dict[str, Any]) -> Dict[str, Any]:
        protocol = self._lower(
            self._first_present(
                rf_features,
                "rf_behavior_protocol_hint",
                "rf_protocol",
                "protocol",
                "classified_protocol",
                "protocol_label",
            )
        )

        behavior_pattern = self._lower(
            self._first_present(
                rf_features,
                "rf_behavior_pattern",
                "behavior_pattern",
            )
        )

        behavior_subtype = self._lower(
            self._first_present(
                rf_features,
                "rf_behavior_subtype",
                "behavior_subtype",
            )
        )

        interval_avg = self._to_float(
            self._first_present(
                rf_features,
                "rf_interval_avg",
                "interval_avg",
                "rf_interval_mean",
                "interval_mean",
            ),
            default=None,
        )

        interval_cv = self._to_float(
            self._first_present(
                rf_features,
                "rf_interval_cv",
                "interval_cv",
            ),
            default=None,
        )

        burst_clusters = self._to_int(
            self._first_present(
                rf_features,
                "rf_burst_clusters",
                "burst_clusters",
            ),
            default=0,
        )

        burst_ratio = self._to_float(
            self._first_present(
                rf_features,
                "rf_burst_ratio",
                "burst_ratio",
            ),
            default=0.0,
        )

        stability_score = self._to_float(
            self._first_present(
                rf_features,
                "rf_stability_score",
                "stability_score",
            ),
            default=0.0,
        )

        periodicity_score = self._to_float(
            self._first_present(
                rf_features,
                "rf_periodicity_score",
                "periodicity_score",
            ),
            default=0.0,
        )

        behavior_confidence = self._to_float(
            self._first_present(
                rf_features,
                "rf_behavior_confidence",
                "behavior_confidence",
            ),
            default=0.0,
        )

        frequency_mhz = self._to_float(
            self._first_present(
                rf_features,
                "rf_behavior_frequency_mhz",
                "rf_frequency_mhz",
                "frequency_mhz",
                "freq_mhz",
                "center_freq_mhz",
            ),
            default=None,
        )

        rf_band = self._infer_band(frequency_mhz)

        return {
            "protocol": protocol,
            "behavior_pattern": behavior_pattern,
            "behavior_subtype": behavior_subtype,
            "interval_avg": interval_avg,
            "interval_cv": interval_cv,
            "burst_clusters": burst_clusters,
            "burst_ratio": burst_ratio,
            "stability_score": stability_score,
            "periodicity_score": periodicity_score,
            "behavior_confidence": behavior_confidence,
            "frequency_mhz": frequency_mhz,
            "rf_band": rf_band,
            "raw_features": rf_features,
        }

    # -------------------------------------------------------------------------
    # CANDIDATE MODEL
    # -------------------------------------------------------------------------

    def _build_candidates(self, f: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        candidates: Dict[str, Dict[str, Any]] = {}

        for key, candidate in (
            ("beaconing_device", self._candidate_beaconing(f)),
            ("telemetry_sensor", self._candidate_telemetry_sensor(f)),
            ("user_triggered_control", self._candidate_user_triggered_control(f)),
            ("high_activity_network_node", self._candidate_high_activity_network_node(f)),
            ("asset_tag_or_lowrate_endpoint", self._candidate_asset_tag_or_lowrate_endpoint(f)),
            ("event_driven_endpoint", self._candidate_event_driven_endpoint(f)),
        ):
            if candidate is not None:
                candidates[key] = candidate

        return candidates

    # -------------------------------------------------------------------------
    # CANDIDATES
    # -------------------------------------------------------------------------

    def _candidate_beaconing(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        score = 0.0
        reasoning: List[str] = []
        tags: List[str] = []

        if f["behavior_subtype"] == "beaconing":
            score += 0.42
            reasoning.append("Behavior subtype explicitly indicates beaconing.")
            tags.append("subtype:beaconing")

        if f["behavior_pattern"] == "periodic":
            score += 0.18
            reasoning.append("Periodic behavior supports beacon-like transmissions.")
            tags.append("pattern:periodic")

        if f["interval_avg"] is not None and 0.08 <= f["interval_avg"] <= 0.20:
            score += 0.18
            reasoning.append("Short fixed interval is consistent with advertising/beacon behavior.")
            tags.append("interval:short_periodic")

        if f["periodicity_score"] >= 0.75:
            score += 0.12
            reasoning.append("High periodicity supports stable beaconing.")
            tags.append("periodicity:high")

        if f["protocol"] == "ble":
            score += 0.10
            reasoning.append("BLE protocol hint strengthens beacon/advertiser interpretation.")
            tags.append("protocol:ble")

        if score < 0.25:
            return None

        ecosystem = "Bluetooth" if f["protocol"] == "ble" else "RF Beaconing"
        device_class = "Beaconing Device Candidate"
        if f["protocol"] == "ble":
            device_class = "BLE Advertiser / Beacon Candidate"

        return self._candidate(
            score=score,
            behavior_pattern="periodic",
            behavior_subtype="beaconing",
            device_role="Periodic Advertiser",
            device_class=device_class,
            ecosystem=ecosystem,
            reasoning=reasoning,
            tags=tags,
            f=f,
        )

    def _candidate_telemetry_sensor(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        score = 0.0
        reasoning: List[str] = []
        tags: List[str] = []

        if f["behavior_subtype"] == "scheduled_telemetry":
            score += 0.38
            reasoning.append("Behavior subtype explicitly indicates scheduled telemetry.")
            tags.append("subtype:scheduled_telemetry")

        if f["behavior_pattern"] in {"periodic", "stable_intermittent"}:
            score += 0.16
            reasoning.append("Stable periodic/intermittent timing matches telemetry workflows.")
            tags.append(f"pattern:{f['behavior_pattern']}")

        if f["interval_avg"] is not None and 1.0 <= f["interval_avg"] <= 120.0:
            score += 0.18
            reasoning.append("Interval range matches low-rate telemetry or sensor updates.")
            tags.append("interval:telemetry_range")

        if f["stability_score"] >= 0.60:
            score += 0.10
            reasoning.append("Stable timing supports scheduled reporting behavior.")
            tags.append("stability:good")

        if f["protocol"] in {"zigbee", "lora"}:
            score += 0.12
            reasoning.append("Protocol hint is compatible with telemetry-oriented endpoints.")
            tags.append(f"protocol:{f['protocol']}")

        if score < 0.25:
            return None

        ecosystem = "IoT"
        if f["protocol"] == "zigbee":
            ecosystem = "Zigbee"
        elif f["protocol"] == "lora":
            ecosystem = "LPWAN"

        device_class = "Telemetry Sensor Candidate"
        if f["protocol"] == "zigbee":
            device_class = "Zigbee Telemetry Sensor Candidate"
        elif f["protocol"] == "lora":
            device_class = "LPWAN Telemetry Node Candidate"

        return self._candidate(
            score=score,
            behavior_pattern=f["behavior_pattern"] or "stable_intermittent",
            behavior_subtype=f["behavior_subtype"] or "scheduled_telemetry",
            device_role="Telemetry Endpoint",
            device_class=device_class,
            ecosystem=ecosystem,
            reasoning=reasoning,
            tags=tags,
            f=f,
        )

    def _candidate_user_triggered_control(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        score = 0.0
        reasoning: List[str] = []
        tags: List[str] = []

        if f["behavior_subtype"] == "user_triggered_bursts":
            score += 0.40
            reasoning.append("Behavior subtype explicitly indicates user-triggered bursts.")
            tags.append("subtype:user_triggered_bursts")

        if f["behavior_pattern"] == "bursty":
            score += 0.20
            reasoning.append("Bursty activity supports short command/control emission behavior.")
            tags.append("pattern:bursty")

        if f["burst_clusters"] >= 2:
            score += 0.15
            reasoning.append("Multiple burst clusters are consistent with repeated control actions.")
            tags.append("bursts:multiple_clusters")

        if f["burst_ratio"] >= 0.20:
            score += 0.10
            reasoning.append("High burst ratio supports clustered short transmissions.")
            tags.append("burst_ratio:high")

        if f["rf_band"] == "SubGHz":
            score += 0.10
            reasoning.append("Sub-GHz operation is common for remotes and simple control devices.")
            tags.append("band:subghz")

        if score < 0.25:
            return None

        ecosystem = "SubGHz / RF Control" if f["rf_band"] == "SubGHz" else "RF Control"
        return self._candidate(
            score=score,
            behavior_pattern="bursty",
            behavior_subtype=f["behavior_subtype"] or "user_triggered_bursts",
            device_role="User-Triggered Control Endpoint",
            device_class="Remote / Control Device Candidate",
            ecosystem=ecosystem,
            reasoning=reasoning,
            tags=tags,
            f=f,
        )

    def _candidate_high_activity_network_node(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        score = 0.0
        reasoning: List[str] = []
        tags: List[str] = []

        if f["behavior_pattern"] == "continuous":
            score += 0.35
            reasoning.append("Continuous activity is consistent with an active network node.")
            tags.append("pattern:continuous")

        if f["behavior_subtype"] == "session_traffic":
            score += 0.18
            reasoning.append("Session traffic subtype supports network-node behavior.")
            tags.append("subtype:session_traffic")

        if f["interval_avg"] is not None and f["interval_avg"] <= 0.05:
            score += 0.12
            reasoning.append("Very short repeat interval indicates sustained traffic flow.")
            tags.append("interval:very_short")

        if f["protocol"] in {"wifi", "802.11", "80211"}:
            score += 0.18
            reasoning.append("WiFi protocol hint strongly supports network-node interpretation.")
            tags.append("protocol:wifi")

        if f["rf_band"] in {"2.4GHz", "5GHz"}:
            score += 0.07
            reasoning.append("Band placement is compatible with common network-device operation.")
            tags.append(f"band:{f['rf_band'].lower()}")

        if score < 0.25:
            return None

        ecosystem = "WiFi" if f["protocol"] in {"wifi", "802.11", "80211"} else "Network RF"
        device_class = "High-Activity Network Node Candidate"
        if ecosystem == "WiFi":
            device_class = "WiFi Client / AP Activity Candidate"

        return self._candidate(
            score=score,
            behavior_pattern="continuous",
            behavior_subtype=f["behavior_subtype"] or "session_traffic",
            device_role="High-Activity Network Node",
            device_class=device_class,
            ecosystem=ecosystem,
            reasoning=reasoning,
            tags=tags,
            f=f,
        )

    def _candidate_asset_tag_or_lowrate_endpoint(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        score = 0.0
        reasoning: List[str] = []
        tags: List[str] = []

        if f["behavior_subtype"] == "low_rate_polling":
            score += 0.34
            reasoning.append("Low-rate polling subtype supports low-duty-cycle endpoint behavior.")
            tags.append("subtype:low_rate_polling")

        if f["behavior_pattern"] in {"stable_intermittent", "periodic"}:
            score += 0.15
            reasoning.append("Stable intermittent timing supports a low-rate endpoint.")
            tags.append(f"pattern:{f['behavior_pattern']}")

        if f["interval_avg"] is not None and 0.5 <= f["interval_avg"] <= 3.0:
            score += 0.18
            reasoning.append("Interval range matches asset-tag or low-rate sensor behavior.")
            tags.append("interval:low_rate_window")

        if f["stability_score"] >= 0.55:
            score += 0.10
            reasoning.append("Timing stability supports repeated low-rate behavior.")
            tags.append("stability:moderate_or_better")

        if f["protocol"] == "ble":
            score += 0.08
            reasoning.append("BLE hint is compatible with tags and low-rate endpoints.")
            tags.append("protocol:ble")

        if score < 0.25:
            return None

        ecosystem = "Bluetooth" if f["protocol"] == "ble" else "IoT / Tracking"
        device_class = "Low-Rate Endpoint Candidate"
        if f["protocol"] == "ble":
            device_class = "BLE Tag / Low-Rate Peripheral Candidate"

        return self._candidate(
            score=score,
            behavior_pattern=f["behavior_pattern"] or "stable_intermittent",
            behavior_subtype=f["behavior_subtype"] or "low_rate_polling",
            device_role="Low-Rate Endpoint",
            device_class=device_class,
            ecosystem=ecosystem,
            reasoning=reasoning,
            tags=tags,
            f=f,
        )

    def _candidate_event_driven_endpoint(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        score = 0.0
        reasoning: List[str] = []
        tags: List[str] = []

        if f["behavior_subtype"] in {"event_driven_activity", "nonperiodic_chatter"}:
            score += 0.30
            reasoning.append("Subtype indicates event-driven or non-periodic activity.")
            tags.append(f"subtype:{f['behavior_subtype']}")

        if f["behavior_pattern"] in {"irregular", "opportunistic"}:
            score += 0.18
            reasoning.append("Irregular/opportunistic behavior supports event-driven activity.")
            tags.append(f"pattern:{f['behavior_pattern']}")

        if f["interval_cv"] is not None and f["interval_cv"] >= 0.50:
            score += 0.12
            reasoning.append("High interval variability supports non-scheduled activity.")
            tags.append("variability:high")

        if f["burst_ratio"] < 0.20:
            score += 0.06
            reasoning.append("Low burst dominance suggests opportunistic events rather than control bursts.")
            tags.append("burst_ratio:not_control_heavy")

        if score < 0.22:
            return None

        return self._candidate(
            score=score,
            behavior_pattern=f["behavior_pattern"] or "irregular",
            behavior_subtype=f["behavior_subtype"] or "event_driven_activity",
            device_role="Event-Driven Endpoint",
            device_class="Event-Driven Device Candidate",
            ecosystem="General RF / IoT",
            reasoning=reasoning,
            tags=tags,
            f=f,
        )

    # -------------------------------------------------------------------------
    # CANDIDATE HELPER
    # -------------------------------------------------------------------------

    def _candidate(
        self,
        score: float,
        behavior_pattern: str,
        behavior_subtype: str,
        device_role: str,
        device_class: str,
        ecosystem: str,
        reasoning: List[str],
        tags: List[str],
        f: Dict[str, Any],
    ) -> Dict[str, Any]:
        base_conf = f["behavior_confidence"] or 0.0
        stability = f["stability_score"] or 0.0
        periodicity = f["periodicity_score"] or 0.0

        fused = (
            0.55 * min(1.0, score) +
            0.20 * base_conf +
            0.15 * stability +
            0.10 * periodicity
        )

        return {
            "score": max(0.0, min(1.0, fused)),
            "behavior_pattern": behavior_pattern,
            "behavior_subtype": behavior_subtype,
            "device_role": device_role,
            "device_class": device_class,
            "ecosystem": ecosystem,
            "reasoning": reasoning,
            "tags": tags,
        }

    # -------------------------------------------------------------------------
    # UTILS
    # -------------------------------------------------------------------------

    def _confidence_label(self, value: float) -> str:
        if value >= self.CONFIDENCE_HIGH:
            return "high"
        if value >= self.CONFIDENCE_MEDIUM:
            return "medium"
        if value >= self.CONFIDENCE_LOW:
            return "low"
        if value > 0:
            return "weak"
        return "unknown"

    def _infer_band(self, freq_mhz: Optional[float]) -> Optional[str]:
        if not freq_mhz:
            return None
        if 2400.0 <= freq_mhz <= 2500.0:
            return "2.4GHz"
        if 4900.0 <= freq_mhz <= 5900.0:
            return "5GHz"
        if 300.0 <= freq_mhz <= 1000.0:
            return "SubGHz"
        return "Unknown"

    def _first_present(self, data: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in data and data.get(key) is not None:
                return data.get(key)
        return None

    def _to_float(self, value: Any, default: Optional[float] = 0.0) -> Optional[float]:
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    def _to_int(self, value: Any, default: int = 0) -> int:
        try:
            if value is None:
                return default
            return int(value)
        except Exception:
            return default

    def _lower(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        return str(value).strip().lower()
