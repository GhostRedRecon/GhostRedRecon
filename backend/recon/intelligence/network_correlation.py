# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF NETWORK CORRELATION ENGINE
# FILE:         backend/recon/intelligence/network_correlation.py
#
# VERSION:      v5.0.0 (PHASE-3 NETWORK INTELLIGENCE + CONSERVATIVE COHESION HARDENING)
# UPDATED:      2026-03-16
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is an RF reconnaissance and device intelligence platform built for
# red-team operations. This module correlates device-level RF observations into
# larger RF ecosystems / networks so the platform can reason about coordinated
# wireless environments instead of isolated emitters.
#
# This engine is protocol-aware but packet-decoding-agnostic. It operates on
# behavioral and RF metadata produced by upstream intelligence layers.
#
# This layer should answer questions such as:
#
# • Which emitters likely belong to the same RF ecosystem?
# • Is this device part of an existing wireless network or a standalone source?
# • How mature / stable is the inferred network?
# • How strong is the evidence for membership?
# • What reasoning supports the assignment?
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# ReconEngine / SignalEngine
#     ↓
# DeviceBehavior / DeviceIntelligence / DeviceFusion
#     ↓
# RFNetworkCorrelationEngine   ← THIS MODULE
#     ↓
# Intel API / Reporting / Graph Layer / Sweep Prioritization / Hunt Console
#
#
# INPUT MODEL
# -----------------------------------------------------------------------------
# correlate(device_id, freq_mhz, rf_features)
#
# rf_features may include:
#
# • rf_protocol / protocol / classified_protocol / protocol_label
# • rf_protocol_confidence
# • rf_behavior_pattern
# • rf_behavior_subtype
# • rf_behavior_device_role
# • rf_behavior_ecosystem
# • rf_behavior_confidence
# • rf_band
# • rf_interval_avg
# • rf_interval_cv
# • power_db / rf_power_db
#
#
# OUTPUT MODEL
# -----------------------------------------------------------------------------
# • rf_network_id
# • rf_network_protocol
# • rf_network_ecosystem
# • rf_network_size
# • rf_network_channels
# • rf_network_channel_span_mhz
# • rf_network_centroid_mhz
# • rf_network_behaviors
# • rf_network_device_roles
# • rf_network_confidence
# • rf_network_confidence_label
# • rf_network_maturity
# • rf_network_assignment_score
# • rf_network_member_score
# • rf_network_reasoning
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. NETWORK-FIRST RF INTELLIGENCE
# -----------------------------------------------------------------------------
# RF environments are ecosystems, not isolated devices.
#
#
# 2. MULTI-EVIDENCE CORRELATION
# -----------------------------------------------------------------------------
# Network assignment should combine:
# • protocol match
# • ecosystem alignment
# • RF band compatibility
# • frequency locality
# • temporal continuity
# • behavioral coherence
# • role consistency
# • confidence-aware weighting
#
#
# 3. CONSERVATIVE GROUPING
# -----------------------------------------------------------------------------
# Avoid over-merging unrelated devices in dense RF environments.
# False-positive grouping is more harmful than delayed grouping.
#
#
# 4. REALTIME SAFE
# -----------------------------------------------------------------------------
# Bounded state, deterministic scoring, low CPU overhead, explainable behavior.
#
#
# 5. EXPLAINABLE OUTPUT
# -----------------------------------------------------------------------------
# Every assignment should be understandable for debugging, reporting, and API use.
#
#
# 6. LIFECYCLE-AWARE NETWORK MEMORY
# -----------------------------------------------------------------------------
# Networks and members should decay naturally when observations go stale.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • grouping devices into RF ecosystems / networks
# • maintaining network state over time
# • scoring membership confidence
# • tracking network maturity / persistence
# • exposing explainable network summaries
# • preserving minimal evidence for debugging and reporting
#
#
# This module is NOT responsible for:
#
# • RF detection
# • SDR control
# • packet decoding
# • exact product attribution
# • exploit assessment
#
# =============================================================================

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


class RFNetworkCorrelationEngine:
    VERSION = "5.0.0"

    # -------------------------------------------------------------------------
    # Lifecycle controls
    # -------------------------------------------------------------------------
    NETWORK_TIMEOUT_SEC = 180.0
    MEMBER_TIMEOUT_SEC = 240.0
    STALE_ACTIVITY_SEC = 60.0

    # -------------------------------------------------------------------------
    # Assignment controls
    # -------------------------------------------------------------------------
    DEFAULT_CLUSTER_WIDTH_MHZ = 5.0
    ASSIGNMENT_THRESHOLD = 0.58
    HARD_REJECT_DELTA_FACTOR = 2.4

    # -------------------------------------------------------------------------
    # Protocol-specific clustering
    # -------------------------------------------------------------------------
    PROTOCOL_CLUSTER_WIDTHS_MHZ = {
        "wifi": 25.0,
        "ble": 4.0,
        "zigbee": 3.0,
        "lora": 1.5,
        "subghz": 2.5,
        "unknown": 5.0,
    }

    def __init__(self) -> None:
        self.networks: Dict[str, Dict[str, Any]] = {}
        self._network_counter = 0

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def correlate(
        self,
        device_id: str,
        freq_mhz: float,
        rf_features: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """
        Correlate a device-level RF observation into an RF network / ecosystem.

        Returns:
            Network summary dict when assignment is possible.
            None when evidence is too weak to correlate safely.
        """
        if not device_id:
            return None

        f = self._normalize_features(freq_mhz=freq_mhz, rf_features=rf_features or {})
        if f["protocol"] is None and f["ecosystem"] is None:
            return None

        now = time.time()
        self.cleanup(now=now)

        best_network_id, best_score, best_reasoning = self._find_best_network(f=f, now=now)

        if best_network_id is None or best_score < self.ASSIGNMENT_THRESHOLD:
            best_network_id = self._create_network(f=f, now=now)
            best_reasoning = [
                "Created new network because no existing network met the assignment threshold."
            ]
            best_score = 0.60

        network = self.networks[best_network_id]
        member_score = self._update_network(network=network, device_id=device_id, f=f, now=now)

        return self._build_network_summary(
            network_id=best_network_id,
            network=network,
            assignment_score=best_score,
            assignment_reasoning=best_reasoning,
            member_score=member_score,
            now=now,
        )

    def cleanup(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()

        for network_id in list(self.networks.keys()):
            network = self.networks[network_id]

            expired_members = [
                member_id
                for member_id, member_state in network["member_state"].items()
                if now - member_state["last_seen"] > self.MEMBER_TIMEOUT_SEC
            ]

            for member_id in expired_members:
                del network["member_state"][member_id]
                network["devices"].discard(member_id)

            if not network["member_state"] and now - network["last_seen"] > self.NETWORK_TIMEOUT_SEC:
                del self.networks[network_id]

    def state(self) -> Dict[str, Any]:
        now = time.time()
        self.cleanup(now=now)

        active_networks: List[Dict[str, Any]] = []

        for network_id, network in self.networks.items():
            confidence = self._network_confidence(network, now=now)
            active_networks.append(
                {
                    "network_id": network_id,
                    "protocol": network["protocol"] or "unknown",
                    "ecosystem": network["ecosystem"] or "unknown",
                    "rf_band": network["rf_band"] or "unknown",
                    "devices": len(network["devices"]),
                    "core_members": self._core_member_count(network),
                    "peak_member_count": network["peak_member_count"],
                    "channels": len(network["channels"]),
                    "channel_span_mhz": round(self._channel_span(network), 4),
                    "freq_centroid_mhz": round(network["freq_centroid_mhz"], 4)
                    if network["freq_centroid_mhz"] is not None else None,
                    "confidence": round(confidence, 4),
                    "confidence_label": self._confidence_label(confidence),
                    "maturity": self._network_maturity(network, now=now),
                    "observation_count": network["observation_count"],
                    "behavior_count": len(network["behaviors"]),
                    "role_count": len(network["device_roles"]),
                    "last_seen_age_sec": round(max(0.0, now - network["last_seen"]), 3),
                    "created_age_sec": round(max(0.0, now - network["created"]), 3),
                }
            )

        active_networks.sort(
            key=lambda x: (
                x["confidence"],
                x["core_members"],
                x["devices"],
                x["observation_count"],
                -x["last_seen_age_sec"],
            ),
            reverse=True,
        )

        return {
            "version": self.VERSION,
            "network_count": len(self.networks),
            "networks": active_networks,
        }

    # =========================================================================
    # NORMALIZATION
    # =========================================================================

    def _normalize_features(self, freq_mhz: float, rf_features: Dict[str, Any]) -> Dict[str, Any]:
        protocol_raw = self._first_present(
            rf_features,
            "rf_protocol",
            "protocol",
            "classified_protocol",
            "protocol_label",
        )
        protocol = self._normalize_protocol(protocol_raw)

        behavior_pattern = self._lower(
            self._first_present(rf_features, "rf_behavior_pattern", "behavior_pattern")
        )
        behavior_subtype = self._lower(
            self._first_present(rf_features, "rf_behavior_subtype", "behavior_subtype")
        )
        device_role = self._lower(
            self._first_present(rf_features, "rf_behavior_device_role", "device_role")
        )
        ecosystem = self._first_present(rf_features, "rf_behavior_ecosystem", "ecosystem")

        rf_band = self._first_present(rf_features, "rf_band")
        if rf_band is None:
            rf_band = self._infer_band(freq_mhz)

        interval_avg = self._to_float(
            self._first_present(rf_features, "rf_interval_avg", "interval_avg"),
            None,
        )
        interval_cv = self._to_float(
            self._first_present(rf_features, "rf_interval_cv", "interval_cv"),
            None,
        )

        behavior_confidence = self._to_float(
            self._first_present(rf_features, "rf_behavior_confidence", "behavior_confidence"),
            0.0,
        )
        protocol_confidence = self._to_float(
            self._first_present(rf_features, "rf_protocol_confidence", "protocol_confidence"),
            0.0,
        )
        power_db = self._to_float(
            self._first_present(rf_features, "rf_power_db", "power_db"),
            None,
        )

        ecosystem = ecosystem or self._ecosystem_from_protocol(protocol, rf_band)

        return {
            "protocol": protocol,
            "behavior_pattern": behavior_pattern,
            "behavior_subtype": behavior_subtype,
            "device_role": device_role,
            "ecosystem": ecosystem,
            "rf_band": rf_band,
            "freq_mhz": float(freq_mhz),
            "interval_avg": interval_avg,
            "interval_cv": interval_cv,
            "behavior_confidence": behavior_confidence,
            "protocol_confidence": protocol_confidence,
            "power_db": power_db,
            "raw_features": rf_features,
        }

    # =========================================================================
    # NETWORK SEARCH
    # =========================================================================

    def _find_best_network(
        self,
        f: Dict[str, Any],
        now: float,
    ) -> Tuple[Optional[str], float, List[str]]:
        best_network_id: Optional[str] = None
        best_score = 0.0
        best_reasoning: List[str] = []

        for network_id, network in self.networks.items():
            score, reasoning = self._score_network_fit(network=network, f=f, now=now)
            if score > best_score:
                best_network_id = network_id
                best_score = score
                best_reasoning = reasoning

        return best_network_id, best_score, best_reasoning

    def _score_network_fit(
        self,
        network: Dict[str, Any],
        f: Dict[str, Any],
        now: float,
    ) -> Tuple[float, List[str]]:
        score = 0.0
        reasoning: List[str] = []

        # ---------------------------------------------------------------------
        # Hard compatibility gates
        # ---------------------------------------------------------------------
        if network["protocol"] and f["protocol"] and network["protocol"] != f["protocol"]:
            return 0.0, ["Hard reject: protocol mismatch."]

        if network["rf_band"] and f["rf_band"] and network["rf_band"] != f["rf_band"]:
            if not self._bands_compatible(network["rf_band"], f["rf_band"]):
                return 0.0, ["Hard reject: RF band mismatch."]

        cluster_width = self._cluster_width_for_protocol(f["protocol"] or network["protocol"])
        centroid = network["freq_centroid_mhz"]

        if centroid is not None:
            delta = abs(centroid - f["freq_mhz"])
            if delta > cluster_width * self.HARD_REJECT_DELTA_FACTOR:
                return 0.0, [f"Hard reject: frequency too far from centroid (Δ={delta:.2f} MHz)."]

        # ---------------------------------------------------------------------
        # Positive evidence
        # ---------------------------------------------------------------------
        if network["protocol"] and f["protocol"] and network["protocol"] == f["protocol"]:
            protocol_bonus = 0.24 + min(0.10, f["protocol_confidence"] * 0.10)
            score += protocol_bonus
            reasoning.append("Protocol matches existing network.")

        if network["ecosystem"] and f["ecosystem"]:
            if network["ecosystem"] == f["ecosystem"]:
                score += 0.13
                reasoning.append("Ecosystem matches existing network.")
            else:
                score -= 0.04
                reasoning.append("Ecosystem differs from current network profile.")

        if network["rf_band"] and f["rf_band"] and network["rf_band"] == f["rf_band"]:
            score += 0.10
            reasoning.append("RF band matches existing network.")

        if centroid is not None:
            delta = abs(centroid - f["freq_mhz"])
            if delta <= cluster_width:
                closeness = 1.0 - (delta / max(cluster_width, 0.001))
                score += 0.24 * closeness
                reasoning.append(f"Frequency is near network centroid (Δ={delta:.2f} MHz).")
            elif delta <= cluster_width * 1.6:
                score += 0.05
                reasoning.append(f"Frequency is near the network edge (Δ={delta:.2f} MHz).")

        if f["behavior_pattern"] and f["behavior_pattern"] in network["behaviors"]:
            score += 0.09 + min(0.04, f["behavior_confidence"] * 0.04)
            reasoning.append("Behavior pattern matches prior network observations.")

        if f["behavior_subtype"] and f["behavior_subtype"] in network["behavior_subtypes"]:
            score += 0.05
            reasoning.append("Behavior subtype aligns with prior observations.")

        if f["device_role"] and f["device_role"] in network["device_roles"]:
            score += 0.08
            reasoning.append("Device role aligns with existing members.")

        recency_sec = max(0.0, now - network["last_seen"])
        if recency_sec <= 15.0:
            score += 0.10
            reasoning.append("Recent network activity supports continuity.")
        elif recency_sec <= 60.0:
            score += 0.05
            reasoning.append("Network was active recently.")
        elif recency_sec > self.STALE_ACTIVITY_SEC:
            score -= 0.04
            reasoning.append("Network activity is becoming stale.")

        maturity = self._network_maturity(network, now=now)
        if maturity in {"mature", "stable"}:
            score += 0.05
            reasoning.append("Network maturity supports assignment confidence.")

        score += min(0.07, 0.02 * len(network["devices"]))
        score += min(0.05, 0.008 * network["observation_count"])

        # Slight penalty when the network is very broad without strong maturity.
        channel_span = self._channel_span(network)
        if channel_span > cluster_width * 1.5 and maturity in {"new", "forming"}:
            score -= 0.05
            reasoning.append("Wide frequency spread reduces confidence in a young network.")

        final_score = max(0.0, min(1.0, score))
        return final_score, reasoning

    # =========================================================================
    # NETWORK LIFECYCLE
    # =========================================================================

    def _create_network(self, f: Dict[str, Any], now: float) -> str:
        self._network_counter += 1
        protocol_label = f["protocol"] or "unknown"
        network_id = f"{protocol_label}_network_{self._network_counter:04d}"

        self.networks[network_id] = {
            "network_id": network_id,
            "protocol": f["protocol"],
            "ecosystem": f["ecosystem"],
            "rf_band": f["rf_band"],
            "created": now,
            "last_seen": now,
            "channels": set(),
            "devices": set(),
            "behaviors": set(),
            "behavior_subtypes": set(),
            "device_roles": set(),
            "member_state": {},
            "freq_min_mhz": None,
            "freq_max_mhz": None,
            "freq_centroid_mhz": None,
            "weighted_freq_sum": 0.0,
            "weighted_freq_weight": 0.0,
            "observation_count": 0,
            "peak_member_count": 0,
            "evidence_counters": {
                "protocol_matches": 0,
                "ecosystem_matches": 0,
                "behavior_matches": 0,
                "role_matches": 0,
            },
        }
        return network_id

    def _update_network(
        self,
        network: Dict[str, Any],
        device_id: str,
        f: Dict[str, Any],
        now: float,
    ) -> float:
        network["last_seen"] = now
        network["observation_count"] += 1
        network["devices"].add(device_id)
        network["channels"].add(round(f["freq_mhz"], 3))
        network["peak_member_count"] = max(network["peak_member_count"], len(network["devices"]))

        if f["behavior_pattern"]:
            network["behaviors"].add(f["behavior_pattern"])
            network["evidence_counters"]["behavior_matches"] += 1

        if f["behavior_subtype"]:
            network["behavior_subtypes"].add(f["behavior_subtype"])

        if f["device_role"]:
            network["device_roles"].add(f["device_role"])
            network["evidence_counters"]["role_matches"] += 1

        if f["protocol"] and network["protocol"] == f["protocol"]:
            network["evidence_counters"]["protocol_matches"] += 1

        if f["ecosystem"] and network["ecosystem"] == f["ecosystem"]:
            network["evidence_counters"]["ecosystem_matches"] += 1

        member = network["member_state"].get(device_id)
        if member is None:
            member = {
                "first_seen": now,
                "last_seen": now,
                "observation_count": 0,
                "last_freq_mhz": f["freq_mhz"],
                "protocol": f["protocol"],
                "device_role": f["device_role"],
                "behavior_pattern": f["behavior_pattern"],
                "stability_score": 0.0,
                "confidence": 0.0,
            }
            network["member_state"][device_id] = member

        member["last_seen"] = now
        member["observation_count"] += 1
        member["last_freq_mhz"] = f["freq_mhz"]
        member["protocol"] = f["protocol"] or member["protocol"]
        member["device_role"] = f["device_role"] or member["device_role"]
        member["behavior_pattern"] = f["behavior_pattern"] or member["behavior_pattern"]
        member["stability_score"] = self._member_stability_score(member=member, now=now)
        member["confidence"] = self._member_confidence(member=member, f=f, now=now)

        self._update_frequency_footprint(network, f["freq_mhz"], f.get("protocol_confidence", 0.0))
        return member["confidence"]

    def _update_frequency_footprint(
        self,
        network: Dict[str, Any],
        freq_mhz: float,
        protocol_confidence: float,
    ) -> None:
        if network["freq_min_mhz"] is None or freq_mhz < network["freq_min_mhz"]:
            network["freq_min_mhz"] = freq_mhz
        if network["freq_max_mhz"] is None or freq_mhz > network["freq_max_mhz"]:
            network["freq_max_mhz"] = freq_mhz

        weight = 0.5 + max(0.0, min(1.0, protocol_confidence))
        network["weighted_freq_sum"] += freq_mhz * weight
        network["weighted_freq_weight"] += weight

        if network["weighted_freq_weight"] > 0:
            network["freq_centroid_mhz"] = network["weighted_freq_sum"] / network["weighted_freq_weight"]
        else:
            network["freq_centroid_mhz"] = freq_mhz

    # =========================================================================
    # SUMMARY
    # =========================================================================

    def _build_network_summary(
        self,
        network_id: str,
        network: Dict[str, Any],
        assignment_score: float,
        assignment_reasoning: List[str],
        member_score: float,
        now: float,
    ) -> Dict[str, Any]:
        channels = sorted(network["channels"])
        device_roles = sorted(role for role in network["device_roles"] if role)
        behaviors = sorted(network["behaviors"])

        channel_span = self._channel_span(network)
        confidence = self._network_confidence(network, now=now)
        maturity = self._network_maturity(network, now=now)

        reasoning = list(assignment_reasoning)
        reasoning.append(f"Network currently contains {len(network['devices'])} device(s).")
        reasoning.append(f"Core members observed: {self._core_member_count(network)}.")
        if network["freq_centroid_mhz"] is not None:
            reasoning.append(f"Network centroid is {network['freq_centroid_mhz']:.3f} MHz.")
        if channel_span > 0:
            reasoning.append(f"Observed channel span is {channel_span:.2f} MHz.")

        return {
            "rf_network_id": network_id,
            "rf_network_protocol": network["protocol"] or "unknown",
            "rf_network_ecosystem": network["ecosystem"] or "unknown",
            "rf_network_size": len(network["devices"]),
            "rf_network_channels": channels,
            "rf_network_channel_span_mhz": round(channel_span, 4),
            "rf_network_centroid_mhz": round(network["freq_centroid_mhz"], 4)
            if network["freq_centroid_mhz"] is not None else None,
            "rf_network_behaviors": behaviors,
            "rf_network_device_roles": device_roles,
            "rf_network_assignment_score": round(max(0.0, min(1.0, assignment_score)), 4),
            "rf_network_member_score": round(max(0.0, min(1.0, member_score)), 4),
            "rf_network_confidence": round(confidence, 4),
            "rf_network_confidence_label": self._confidence_label(confidence),
            "rf_network_maturity": maturity,
            "rf_network_reasoning": reasoning,
        }

    # =========================================================================
    # CONFIDENCE / MATURITY
    # =========================================================================

    def _member_stability_score(self, member: Dict[str, Any], now: float) -> float:
        obs_score = min(1.0, member["observation_count"] / 6.0)
        age_sec = max(0.0, now - member["first_seen"])
        age_score = min(1.0, age_sec / 120.0)

        recency_sec = max(0.0, now - member["last_seen"])
        recency_score = 1.0 if recency_sec <= 10 else 0.65 if recency_sec <= 60 else 0.25

        return max(0.0, min(1.0, 0.45 * obs_score + 0.30 * age_score + 0.25 * recency_score))

    def _member_confidence(self, member: Dict[str, Any], f: Dict[str, Any], now: float) -> float:
        stability_score = member.get("stability_score", 0.0)
        obs_score = min(1.0, member["observation_count"] / 6.0)

        role_score = 0.75 if member.get("device_role") else 0.35
        behavior_score = 0.75 if member.get("behavior_pattern") else 0.35

        protocol_score = 0.35 + min(0.65, f.get("protocol_confidence", 0.0))
        power_score = 0.5
        power_db = f.get("power_db")
        if power_db is not None:
            if power_db >= 20:
                power_score = 0.9
            elif power_db >= 10:
                power_score = 0.75
            elif power_db >= 0:
                power_score = 0.6

        score = (
            0.28 * stability_score +
            0.18 * obs_score +
            0.14 * role_score +
            0.14 * behavior_score +
            0.16 * protocol_score +
            0.10 * power_score
        )
        return max(0.0, min(1.0, score))

    def _network_confidence(self, network: Dict[str, Any], now: float) -> float:
        size_score = min(1.0, len(network["devices"]) / 5.0)
        obs_score = min(1.0, network["observation_count"] / 12.0)
        behavior_score = min(1.0, len(network["behaviors"]) / 3.0)
        role_score = 0.35 if not network["device_roles"] else 0.75
        core_score = min(1.0, self._core_member_count(network) / 3.0)

        recency_age = max(0.0, now - network["last_seen"])
        recency_score = 1.0 if recency_age <= 15 else 0.7 if recency_age <= 60 else 0.30

        maturity_bonus = {
            "new": 0.00,
            "forming": 0.03,
            "mature": 0.06,
            "stable": 0.10,
        }.get(self._network_maturity(network, now=now), 0.0)

        score = (
            0.20 * size_score +
            0.20 * obs_score +
            0.12 * behavior_score +
            0.14 * role_score +
            0.20 * core_score +
            0.14 * recency_score +
            maturity_bonus
        )
        return max(0.0, min(1.0, score))

    def _network_maturity(self, network: Dict[str, Any], now: float) -> str:
        age_sec = max(0.0, now - network["created"])
        obs = network["observation_count"]
        core = self._core_member_count(network)
        members = len(network["devices"])

        if obs >= 15 and core >= 2 and age_sec >= 120:
            return "stable"
        if obs >= 8 and members >= 2:
            return "mature"
        if obs >= 3:
            return "forming"
        return "new"

    def _core_member_count(self, network: Dict[str, Any]) -> int:
        count = 0
        for member in network["member_state"].values():
            if member.get("confidence", 0.0) >= 0.62 and member.get("observation_count", 0) >= 3:
                count += 1
        return count

    def _channel_span(self, network: Dict[str, Any]) -> float:
        if network["freq_min_mhz"] is None or network["freq_max_mhz"] is None:
            return 0.0
        return max(0.0, network["freq_max_mhz"] - network["freq_min_mhz"])

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _cluster_width_for_protocol(self, protocol: Optional[str]) -> float:
        if protocol is None:
            return self.DEFAULT_CLUSTER_WIDTH_MHZ
        return self.PROTOCOL_CLUSTER_WIDTHS_MHZ.get(protocol, self.DEFAULT_CLUSTER_WIDTH_MHZ)

    def _bands_compatible(self, band_a: str, band_b: str) -> bool:
        return band_a == band_b

    def _ecosystem_from_protocol(self, protocol: Optional[str], rf_band: Optional[str]) -> Optional[str]:
        if protocol == "wifi":
            return "WiFi"
        if protocol == "ble":
            return "Bluetooth"
        if protocol == "zigbee":
            return "Zigbee"
        if protocol == "lora":
            return "LPWAN"
        if protocol == "subghz":
            return "SubGHz / RF Control"
        if rf_band == "SubGHz":
            return "SubGHz RF"
        return None

    def _normalize_protocol(self, protocol: Any) -> Optional[str]:
        p = self._lower(protocol)
        if p is None:
            return None

        if p in {"wifi", "802.11", "80211", "wlan"}:
            return "wifi"
        if p in {"ble", "bluetooth", "bluetooth le"}:
            return "ble"
        if p in {"zigbee", "802.15.4", "802154"}:
            return "zigbee"
        if p in {"lora", "lora/lorawan", "lorawan"}:
            return "lora"
        if p in {"subghz", "ook", "ask", "fsk_remote", "remote"}:
            return "subghz"
        return p

    def _infer_band(self, freq_mhz: float) -> str:
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

    def _lower(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().lower()
        return text or None

    def _confidence_label(self, value: float) -> str:
        if value >= 0.80:
            return "high"
        if value >= 0.60:
            return "medium"
        if value >= 0.40:
            return "low"
        if value > 0:
            return "weak"
        return "unknown"
