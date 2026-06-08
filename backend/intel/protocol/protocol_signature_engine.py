# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/protocol_signature_engine.py
# VERSION:      v2.0.0 (PRODUCTION GRADE MULTI-HINT PROTOCOL FUSION)
# LAST UPDATED: 2026-03-15
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# Recon / Detection / Signal Pipeline
#     ↓
# Feature Extraction Layer
#     ↓
# ProtocolEngine
#     ↓
# ProtocolSignatureEngine   <-- THIS FILE
#     ↓
# Deterministic protocol scoring
#     ↓
# Explainable ranked protocol candidates
#     ↓
# ProtocolEngine merge / downstream device intelligence
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance and red-team intelligence platform.
# This file performs deterministic protocol inference from RF observations,
# feature-extraction hints, and upstream classification metadata.
#
# It is designed to be:
#   - stateless
#   - deterministic
#   - explainable
#   - schema tolerant
#   - conservative under uncertainty
#   - safe for real-time execution
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
#
# This file IS responsible for:
#   - normalizing inconsistent signal / emitter schemas
#   - scoring protocol candidates from multiple RF hints
#   - ambiguity detection
#   - explainable evidence production
#   - ranked candidate shaping for downstream intelligence layers
#
# This file is NOT responsible for:
#   - SDR control
#   - storage
#   - emitter tracking
#   - device / vendor / product attribution
#   - packet decoding
#   - demodulation
#   - orchestration
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. CONSERVATIVE CLASSIFICATION
#    UNKNOWN is better than a false positive.
#
# 2. MULTI-HINT FUSION
#    Protocol inference must use several weak hints together.
#
# 3. SCHEMA TOLERANCE
#    Accept flattened fields, nested rf_features, legacy names, and list values.
#
# 4. EXPLAINABILITY
#    Every result should include evidence, ambiguity reason, and ranked candidates.
#
# 5. REAL-TIME SAFETY
#    No heavy DSP, no external I/O, no non-deterministic behavior.
#
# 6. DOWNSTREAM USABILITY
#    Output should be immediately consumable by ProtocolEngine, SignalEngine,
#    and device intelligence layers.
#
# =============================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class ProtocolSignatureEngine:
    """
    Deterministic protocol signature engine for GhostRecon.

    Input:
        signal / emitter / record-like dict

    Output:
        dict with:
            - protocol_signature
            - protocol_family
            - protocol_confidence
            - protocol_candidates
            - ranked_protocol_candidates
            - protocol_evidence
            - protocol_score_map
            - protocol_ambiguity
            - normalized_protocol_observation
    """

    VERSION = "2.0.0"

    UNKNOWN_THRESHOLD = 0.43
    MIN_MARGIN = 0.08
    RUNNER_UP_RETAIN_THRESHOLD = 0.20

    WIFI_CENTERS_24 = [
        2412.0, 2417.0, 2422.0, 2427.0, 2432.0, 2437.0, 2442.0,
        2447.0, 2452.0, 2457.0, 2462.0, 2467.0, 2472.0, 2484.0
    ]

    BLE_ADV_CENTERS = [2402.0, 2426.0, 2480.0]
    ZIGBEE_CENTERS = [2405.0 + (5.0 * i) for i in range(16)]
    SUBGHZ_COMMON = [315.0, 390.0, 418.0, 433.05, 433.30, 433.60, 433.92, 868.0, 869.0, 902.0, 915.0]
    WMBUS_CENTERS = [868.30, 868.95, 869.525]
    LORA_CENTERS = [
        433.175, 433.375, 433.775, 433.92,
        867.1, 867.3, 867.5, 867.7, 867.9,
        868.1, 868.3, 868.5, 869.525,
        903.9, 904.1, 904.3, 904.5, 904.7, 904.9, 905.1, 905.3,
        923.3,
    ]

    def classify(self, record: Dict[str, Any]) -> Dict[str, Any]:
        obs = self._normalize(record)
        candidates = self._build_candidate_set(obs)

        scores: Dict[str, float] = {c: 0.0 for c in candidates}
        evidence: Dict[str, List[str]] = {c: [] for c in candidates}
        penalties: Dict[str, List[str]] = {c: [] for c in candidates}

        for proto in candidates:
            if proto == "WIFI":
                self._score_wifi(obs, scores, evidence, penalties)
            elif proto == "BLE":
                self._score_ble(obs, scores, evidence, penalties)
            elif proto == "IEEE_802.15.4_ZIGBEE":
                self._score_zigbee(obs, scores, evidence, penalties)
            elif proto == "LORA":
                self._score_lora(obs, scores, evidence, penalties)
            elif proto == "SUBGHZ_FSK":
                self._score_subghz_fsk(obs, scores, evidence, penalties)
            elif proto == "WIRELESS_MBUS":
                self._score_wireless_mbus(obs, scores, evidence, penalties)
            elif proto == "SUBGHZ_OOK":
                self._score_subghz_ook(obs, scores, evidence, penalties)

        self._apply_consistency_shaping(obs, scores, evidence, penalties)

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        winner, winner_score = ranked[0] if ranked else ("UNKNOWN_PROTOCOL", 0.0)
        runner, runner_score = ranked[1] if len(ranked) > 1 else ("UNKNOWN_PROTOCOL", 0.0)
        margin = round(winner_score - runner_score, 3)

        ambiguous = False
        ambiguity_reason: Optional[str] = None

        if winner_score < self.UNKNOWN_THRESHOLD:
            protocol = "UNKNOWN_PROTOCOL"
            family = "UNKNOWN"
            confidence = round(max(0.0, winner_score), 3)
            ambiguous = True
            ambiguity_reason = "score_below_threshold"
            chosen_evidence = evidence.get(winner, [])[:]
        elif margin < self.MIN_MARGIN:
            protocol = "UNKNOWN_PROTOCOL"
            family = "UNKNOWN"
            confidence = round(max(0.0, winner_score), 3)
            ambiguous = True
            ambiguity_reason = f"low_margin_vs_{runner}"
            chosen_evidence = evidence.get(winner, [])[:] + [f"close_runner_up:{runner}"]
        else:
            protocol = winner
            family = self._protocol_family(protocol)
            confidence = round(max(0.0, min(1.0, winner_score)), 3)
            chosen_evidence = evidence.get(winner, [])[:]

        ranked_candidates = []
        for name, score in ranked[:5]:
            if score <= 0.0:
                continue
            if score < self.RUNNER_UP_RETAIN_THRESHOLD and name != winner:
                continue
            ranked_candidates.append(
                {
                    "protocol": name,
                    "family": self._protocol_family(name),
                    "score": round(score, 3),
                    "evidence": evidence.get(name, [])[:8],
                    "penalties": penalties.get(name, [])[:6],
                }
            )

        return {
            "protocol_signature": protocol,
            "protocol_guess": protocol,
            "protocol_family": family,
            "protocol_confidence": confidence,
            "protocol_candidates": [item["protocol"] for item in ranked_candidates[:3]],
            "ranked_protocol_candidates": ranked_candidates,
            "protocol_evidence": chosen_evidence[:12],
            "protocol_score_map": {k: round(v, 3) for k, v in ranked},
            "protocol_penalty_map": {k: penalties.get(k, [])[:6] for k, _ in ranked},
            "protocol_ambiguity": {
                "ambiguous": ambiguous,
                "reason": ambiguity_reason,
                "winner_margin": margin,
                "runner_up": runner,
                "winner_score": round(winner_score, 3),
                "runner_up_score": round(runner_score, 3),
            },
            "normalized_protocol_observation": obs,
            "signature_engine_version": self.VERSION,
        }

    # -------------------------------------------------------------------------
    # NORMALIZATION
    # -------------------------------------------------------------------------

    def _normalize(self, record: Dict[str, Any]) -> Dict[str, Any]:
        rf = record.get("rf_features", {}) or {}

        freq_mhz = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "frequency_mhz",
                    "freq_mhz",
                    "center_freq_mhz",
                    "center_frequency_mhz",
                    "rf_center_mhz",
                    "rf_frequency_mhz",
                ],
            ),
            0.0,
        )

        bandwidth_mhz = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "bandwidth_mhz",
                    "rf_bandwidth_mhz",
                    "estimated_bandwidth_mhz",
                    "bw_mhz",
                    "rf_width_mhz",
                    "width_mhz",
                ],
            ),
            0.0,
        )

        power_db = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "power_db",
                    "avg_power_db",
                    "rf_power_db",
                ],
            ),
            -120.0,
        )

        channel = self._safe_int(
            self._first_present(
                record,
                rf,
                keys=[
                    "channel",
                    "rf_channel",
                ],
            ),
            None,
        )

        rf_band = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_band",
                    "band",
                    "band_name",
                    "band_type",
                ],
            )
        )

        modulation = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_modulation_hint",
                    "modulation",
                    "modulation_guess",
                    "modulation_type",
                ],
            )
        )

        signal_class = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_signal_class",
                    "signal_class",
                    "classification",
                ],
            )
        )

        signal_type = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "signal_type",
                    "rf_signal_type",
                ],
            )
        )

        shape_hint = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "shape_hint",
                    "rf_shape_hint",
                    "spectral_shape",
                    "shape_class",
                ],
            )
        )

        frame_structure = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "frame_structure",
                    "frame_structure_hint",
                    "rf_frame_structure",
                ],
            )
        )

        protocol_hint = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "protocol_hint",
                    "protocol_family_hint",
                    "rf_protocol_hint",
                    "rf_protocol_family",
                ],
            )
        )

        burst_ms = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "burst_duration_ms",
                    "avg_burst_ms",
                    "burst_ms",
                ],
            ),
            0.0,
        )

        burst_interval_ms = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "burst_interval_ms",
                    "avg_burst_interval_ms",
                    "inter_burst_ms",
                    "period_ms",
                ],
            ),
            0.0,
        )

        symbol_rate = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "symbol_rate_estimate",
                    "symbol_rate",
                    "symbol_rate_ksps",
                    "baud_rate",
                ],
            ),
            0.0,
        )

        periodicity_score = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "periodicity_score",
                    "burst_periodicity",
                    "periodic_score",
                ],
            ),
            0.0,
        )

        ofdm_likelihood = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_ofdm_likelihood",
                    "ofdm_likelihood",
                ],
            ),
            0.0,
        )

        carrier_count = self._safe_int(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_carrier_count",
                    "carrier_count",
                    "subcarrier_count",
                ],
            ),
            0,
        )

        duty_cycle = self._safe_float(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_duty_cycle",
                    "duty_cycle",
                    "burst_ratio",
                ],
            ),
            0.0,
        )

        subghz_profile = self._norm_token(
            self._first_present(
                record,
                rf,
                keys=[
                    "rf_subghz_profile",
                    "subghz_profile",
                ],
            )
        )

        protocol_family_candidates = self._norm_token_list(
            self._first_present(
                record,
                rf,
                keys=[
                    "protocol_family_candidates",
                    "protocol_families",
                    "rf_protocol_family_candidates",
                ],
            )
        )

        return {
            "freq_mhz": freq_mhz,
            "bandwidth_mhz": bandwidth_mhz,
            "power_db": power_db,
            "channel": channel,
            "rf_band": rf_band,
            "modulation": modulation,
            "signal_class": signal_class,
            "signal_type": signal_type,
            "shape_hint": shape_hint,
            "frame_structure": frame_structure,
            "protocol_hint": protocol_hint,
            "burst_ms": burst_ms,
            "burst_interval_ms": burst_interval_ms,
            "symbol_rate": symbol_rate,
            "periodicity_score": periodicity_score,
            "ofdm_likelihood": ofdm_likelihood,
            "carrier_count": carrier_count,
            "duty_cycle": duty_cycle,
            "subghz_profile": subghz_profile,
            "protocol_family_candidates": protocol_family_candidates,
        }

    # -------------------------------------------------------------------------
    # CANDIDATE SELECTION
    # -------------------------------------------------------------------------

    def _build_candidate_set(self, obs: Dict[str, Any]) -> List[str]:
        freq = obs["freq_mhz"]
        band = obs["rf_band"]
        modulation = obs["modulation"]
        protocol_hint = obs["protocol_hint"]
        subghz_profile = obs["subghz_profile"]
        family_candidates = set(obs.get("protocol_family_candidates", []))

        candidates: List[str] = []

        if 2400.0 <= freq <= 2500.0 or band in {"2_4ghz", "2_4", "wifi", "ble", "zigbee"}:
            candidates.extend(["WIFI", "BLE", "IEEE_802.15.4_ZIGBEE"])

        if 250.0 <= freq <= 1000.0 or band in {"subghz", "sub_ghz", "sub-ghz"}:
            candidates.extend(["SUBGHZ_OOK", "SUBGHZ_FSK", "WIRELESS_MBUS", "LORA"])

        if "wifi" in protocol_hint or "802_11" in protocol_hint:
            candidates.append("WIFI")
        if "ble" in protocol_hint or "bluetooth" in protocol_hint:
            candidates.append("BLE")
        if "zigbee" in protocol_hint or "802_15_4" in protocol_hint:
            candidates.append("IEEE_802.15.4_ZIGBEE")
        if "lora" in protocol_hint or "lpwan" in protocol_hint:
            candidates.append("LORA")
        if "wireless_mbus" in protocol_hint or "wmbus" in protocol_hint or "m-bus" in protocol_hint:
            candidates.append("WIRELESS_MBUS")
        if "lora" in subghz_profile or "lpwan" in subghz_profile:
            candidates.append("LORA")
        if "wireless_mbus" in subghz_profile or "wmbus" in subghz_profile or "meter" in subghz_profile:
            candidates.append("WIRELESS_MBUS")

        if modulation in {"ofdm", "multicarrier", "wideband_ofdm_like"}:
            candidates.append("WIFI")
        if modulation in {"gfsk", "gfsk_like"}:
            candidates.extend(["BLE", "SUBGHZ_FSK"])
            if 868.0 <= freq <= 870.0:
                candidates.append("WIRELESS_MBUS")
        if modulation in {"oqpsk", "oqpsk_like", "dsss_oqpsk_like", "dsss"}:
            candidates.append("IEEE_802.15.4_ZIGBEE")
        if modulation in {"lora", "lora_like", "css", "chirp", "chirp_spread_spectrum"}:
            candidates.append("LORA")
        if modulation in {"ook", "ask", "pulse_ook"}:
            candidates.append("SUBGHZ_OOK")

        if "wifi" in family_candidates:
            candidates.append("WIFI")
        if "ble" in family_candidates or "bluetooth" in family_candidates:
            candidates.append("BLE")
        if "zigbee" in family_candidates or "ieee_802_15_4" in family_candidates:
            candidates.append("IEEE_802.15.4_ZIGBEE")
        if "lpwan" in family_candidates or "lora" in family_candidates:
            candidates.append("LORA")
        if "subghz" in family_candidates:
            candidates.extend(["SUBGHZ_FSK", "SUBGHZ_OOK", "WIRELESS_MBUS"])
        if "wireless_mbus" in family_candidates or "wmbus" in family_candidates:
            candidates.append("WIRELESS_MBUS")

        if not candidates:
            candidates = [
                "WIFI",
                "BLE",
                "IEEE_802.15.4_ZIGBEE",
                "SUBGHZ_OOK",
                "SUBGHZ_FSK",
                "WIRELESS_MBUS",
                "LORA",
            ]

        out: List[str] = []
        seen = set()
        for c in candidates:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    # -------------------------------------------------------------------------
    # SCORERS
    # -------------------------------------------------------------------------

    def _score_wifi(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "WIFI"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        channel = obs["channel"]
        modulation = obs["modulation"]
        signal_class = obs["signal_class"]
        shape_hint = obs["shape_hint"]
        frame_structure = obs["frame_structure"]
        protocol_hint = obs["protocol_hint"]
        ofdm = obs["ofdm_likelihood"]
        carriers = obs["carrier_count"]
        band = obs["rf_band"]

        if 2400.0 <= freq <= 2500.0:
            self._bump(scores, evidence, proto, 0.05, "within_2_4ghz_range")

        if band in {"2_4ghz", "wifi"}:
            self._bump(scores, evidence, proto, 0.07, "rf_band_wifi_like")

        nearest_center = self._nearest_distance(freq, self.WIFI_CENTERS_24)
        if nearest_center <= 2.5:
            self._bump(scores, evidence, proto, 0.10, f"near_wifi_channel_center:{nearest_center:.2f}mhz")

        if channel is not None and 1 <= channel <= 14:
            self._bump(scores, evidence, proto, 0.12, "wifi_channel_present")

        if bw >= 16.0:
            self._bump(scores, evidence, proto, 0.32, "wifi_wideband_profile")
        elif bw >= 8.0:
            self._bump(scores, evidence, proto, 0.16, "moderately_wide_profile")

        if modulation in {"ofdm", "wideband_ofdm_like", "multicarrier"}:
            self._bump(scores, evidence, proto, 0.26, f"modulation:{modulation}")

        if signal_class in {"wideband", "multicarrier"}:
            self._bump(scores, evidence, proto, 0.09, f"signal_class:{signal_class}")

        if shape_hint in {"wideband_plateau", "multicarrier_cluster", "ofdm_shelf"}:
            self._bump(scores, evidence, proto, 0.08, f"shape_hint:{shape_hint}")

        if frame_structure in {"packetized_wifi_like", "beacon_like"}:
            self._bump(scores, evidence, proto, 0.08, f"frame_structure:{frame_structure}")

        if "wifi" in protocol_hint or "802_11" in protocol_hint:
            self._bump(scores, evidence, proto, 0.14, f"protocol_hint:{protocol_hint}")

        if ofdm >= 0.75:
            self._bump(scores, evidence, proto, 0.22, "high_ofdm_likelihood")
        elif ofdm >= 0.45:
            self._bump(scores, evidence, proto, 0.10, "moderate_ofdm_likelihood")

        if carriers >= 8:
            self._bump(scores, evidence, proto, 0.08, "multicarrier_count_present")

        if 0.0 < bw < 3.0:
            self._penalize(scores, penalties, proto, 0.18, "too_narrow_for_typical_wifi")

    def _score_ble(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "BLE"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        modulation = obs["modulation"]
        burst_ms = obs["burst_ms"]
        burst_interval_ms = obs["burst_interval_ms"]
        periodicity = obs["periodicity_score"]
        shape_hint = obs["shape_hint"]
        frame_structure = obs["frame_structure"]
        protocol_hint = obs["protocol_hint"]

        nearest_adv = self._nearest_distance(freq, self.BLE_ADV_CENTERS)
        if nearest_adv <= 1.0:
            self._bump(scores, evidence, proto, 0.30, f"near_ble_adv_channel:{nearest_adv:.2f}mhz")
        elif self._is_near_ble_data_channel(freq):
            self._bump(scores, evidence, proto, 0.18, "near_ble_data_channel")

        if 0.7 <= bw <= 2.5:
            self._bump(scores, evidence, proto, 0.22, "ble_like_bandwidth")

        if modulation in {"gfsk", "gfsk_like", "fsk_like"}:
            self._bump(scores, evidence, proto, 0.22, f"modulation:{modulation}")

        if 0.0 < burst_ms <= 8.0:
            self._bump(scores, evidence, proto, 0.06, "short_burst_profile")

        if 10.0 <= burst_interval_ms <= 3000.0:
            self._bump(scores, evidence, proto, 0.04, "recurrent_short_burst_interval")

        if periodicity >= 0.45:
            self._bump(scores, evidence, proto, 0.06, "advertising_like_periodicity")

        if shape_hint in {"narrowband_burst", "short_hop_burst"}:
            self._bump(scores, evidence, proto, 0.05, f"shape_hint:{shape_hint}")

        if frame_structure in {"advertising_burst", "short_control_burst"}:
            self._bump(scores, evidence, proto, 0.06, f"frame_structure:{frame_structure}")

        if "ble" in protocol_hint or "bluetooth" in protocol_hint:
            self._bump(scores, evidence, proto, 0.14, f"protocol_hint:{protocol_hint}")

        if bw >= 8.0:
            self._penalize(scores, penalties, proto, 0.16, "too_wide_for_ble")

    def _score_zigbee(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "IEEE_802.15.4_ZIGBEE"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        modulation = obs["modulation"]
        symbol_rate = obs["symbol_rate"]
        periodicity = obs["periodicity_score"]
        frame_structure = obs["frame_structure"]
        shape_hint = obs["shape_hint"]
        protocol_hint = obs["protocol_hint"]

        nearest_center = self._nearest_distance(freq, self.ZIGBEE_CENTERS)
        if nearest_center <= 1.5:
            self._bump(scores, evidence, proto, 0.25, f"near_zigbee_center:{nearest_center:.2f}mhz")
        elif nearest_center <= 2.5:
            self._bump(scores, evidence, proto, 0.11, "close_to_zigbee_center")

        if 1.0 <= bw <= 3.5:
            self._bump(scores, evidence, proto, 0.28, "zigbee_like_bandwidth")

        if modulation in {"oqpsk", "oqpsk_like", "dsss_oqpsk_like", "dsss"}:
            self._bump(scores, evidence, proto, 0.32, f"modulation:{modulation}")

        if 100.0 <= symbol_rate <= 4000.0:
            self._bump(scores, evidence, proto, 0.07, "low_rate_mesh_telemetry_profile")

        if periodicity >= 0.30:
            self._bump(scores, evidence, proto, 0.05, "sensor_mesh_periodicity")

        if shape_hint in {"narrowband_burst", "dsss_cluster"}:
            self._bump(scores, evidence, proto, 0.05, f"shape_hint:{shape_hint}")

        if frame_structure in {"telemetry_burst", "mesh_control_burst"}:
            self._bump(scores, evidence, proto, 0.07, f"frame_structure:{frame_structure}")

        if "zigbee" in protocol_hint or "802_15_4" in protocol_hint:
            self._bump(scores, evidence, proto, 0.15, f"protocol_hint:{protocol_hint}")

        if bw >= 8.0:
            self._penalize(scores, penalties, proto, 0.16, "too_wide_for_zigbee")

    def _score_lora(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "LORA"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        band = obs["rf_band"]
        modulation = obs["modulation"]
        signal_type = obs["signal_type"]
        shape_hint = obs["shape_hint"]
        protocol_hint = obs["protocol_hint"]
        periodicity = obs["periodicity_score"]
        duty_cycle = obs["duty_cycle"]
        subghz_profile = obs["subghz_profile"]
        nearest_lora = self._nearest_distance(freq, self.LORA_CENTERS)

        if band in {"subghz", "sub_ghz", "sub-ghz"}:
            self._bump(scores, evidence, proto, 0.10, "subghz_band")

        if self._nearest_distance(freq, self.SUBGHZ_COMMON) <= 3.0:
            self._bump(scores, evidence, proto, 0.09, "common_lpwan_band")

        if nearest_lora <= 0.20:
            self._bump(scores, evidence, proto, 0.18, f"exact_lora_bandplan_center:{nearest_lora:.2f}mhz")
        elif nearest_lora <= 0.60:
            self._bump(scores, evidence, proto, 0.09, "near_lora_bandplan_center")

        if modulation in {"lora", "lora_like", "css", "chirp", "chirp_spread_spectrum"}:
            self._bump(scores, evidence, proto, 0.56, f"modulation:{modulation}")

        if shape_hint in {"chirp_sweep", "css_like"}:
            self._bump(scores, evidence, proto, 0.16, f"shape_hint:{shape_hint}")

        if "lora" in protocol_hint or "lpwan" in protocol_hint:
            self._bump(scores, evidence, proto, 0.14, f"protocol_hint:{protocol_hint}")

        if "lora" in subghz_profile or "lpwan" in subghz_profile:
            self._bump(scores, evidence, proto, 0.18, f"subghz_profile:{subghz_profile}")
        if any(token in subghz_profile for token in {"eu868", "us915", "ism433", "eu433", "lorawan"}):
            self._bump(scores, evidence, proto, 0.12, f"regional_profile:{subghz_profile}")

        if signal_type in {"periodic", "burst"}:
            self._bump(scores, evidence, proto, 0.10, f"signal_type:{signal_type}")

        if periodicity >= 0.70:
            self._bump(scores, evidence, proto, 0.12, "strong_periodicity_profile")

        if 0.01 <= duty_cycle <= 0.35:
            self._bump(scores, evidence, proto, 0.08, "low_duty_lpwan_profile")
        elif duty_cycle >= 0.70:
            self._penalize(scores, penalties, proto, 0.14, "high_duty_cycle_unusual_for_lora")

        if 0.05 <= bw <= 0.60:
            self._bump(scores, evidence, proto, 0.10, "narrow_css_like_width")
        elif bw > 2.5:
            self._penalize(scores, penalties, proto, 0.10, "too_wide_for_typical_lora")

    def _score_subghz_fsk(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "SUBGHZ_FSK"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        band = obs["rf_band"]
        modulation = obs["modulation"]
        symbol_rate = obs["symbol_rate"]
        signal_type = obs["signal_type"]
        shape_hint = obs["shape_hint"]
        frame_structure = obs["frame_structure"]
        periodicity = obs["periodicity_score"]
        duty_cycle = obs["duty_cycle"]
        subghz_profile = obs["subghz_profile"]

        if band in {"subghz", "sub_ghz", "sub-ghz"}:
            self._bump(scores, evidence, proto, 0.10, "subghz_band")

        if self._nearest_distance(freq, self.SUBGHZ_COMMON) <= 3.0:
            self._bump(scores, evidence, proto, 0.08, "common_subghz_telemetry_band")

        if modulation in {"fsk", "fsk_like", "2fsk", "gfsk", "gfsk_like"}:
            self._bump(scores, evidence, proto, 0.34, f"modulation:{modulation}")

        if 0.04 <= bw <= 0.80:
            self._bump(scores, evidence, proto, 0.08, "narrow_fsk_width")

        if 5000.0 <= symbol_rate <= 150000.0:
            self._bump(scores, evidence, proto, 0.18, "telemetry_symbol_rate")

        if shape_hint in {"narrowband_burst", "fsk_cluster"}:
            self._bump(scores, evidence, proto, 0.05, f"shape_hint:{shape_hint}")

        if frame_structure in {"telemetry_burst", "metering_burst"}:
            self._bump(scores, evidence, proto, 0.06, f"frame_structure:{frame_structure}")

        if signal_type in {"continuous", "periodic"}:
            self._bump(scores, evidence, proto, 0.06, f"signal_type:{signal_type}")

        if duty_cycle >= 0.60:
            self._bump(scores, evidence, proto, 0.10, "high_duty_telemetry_profile")

        if periodicity >= 0.70:
            self._bump(scores, evidence, proto, 0.04, "periodic_telemetry_pattern")

        if "generic_subghz" in subghz_profile:
            self._bump(scores, evidence, proto, 0.08, f"subghz_profile:{subghz_profile}")
        elif "lora" in subghz_profile:
            self._penalize(scores, penalties, proto, 0.06, "profile_bias_toward_lora")

        if bw >= 2.0:
            self._penalize(scores, penalties, proto, 0.07, "too_wide_for_typical_subghz_fsk")

    def _score_wireless_mbus(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "WIRELESS_MBUS"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        band = obs["rf_band"]
        modulation = obs["modulation"]
        symbol_rate = obs["symbol_rate"]
        signal_type = obs["signal_type"]
        frame_structure = obs["frame_structure"]
        periodicity = obs["periodicity_score"]
        duty_cycle = obs["duty_cycle"]
        subghz_profile = obs["subghz_profile"]
        protocol_hint = obs["protocol_hint"]
        nearest_wmbus = self._nearest_distance(freq, self.WMBUS_CENTERS)
        nearest_lora = self._nearest_distance(freq, self.LORA_CENTERS)

        if band in {"subghz", "sub_ghz", "sub-ghz"}:
            self._bump(scores, evidence, proto, 0.12, "subghz_band")

        if nearest_wmbus <= 0.12:
            self._bump(scores, evidence, proto, 0.30, f"exact_wmbus_center:{nearest_wmbus:.2f}mhz")
        elif nearest_wmbus <= 0.35:
            self._bump(scores, evidence, proto, 0.14, "near_wmbus_center")

        if modulation in {"fsk", "fsk_like", "2fsk", "gfsk", "gfsk_like", "gmsk"}:
            self._bump(scores, evidence, proto, 0.26, f"modulation:{modulation}")

        if frame_structure in {"metering_burst", "telemetry_burst"}:
            self._bump(scores, evidence, proto, 0.24, f"frame_structure:{frame_structure}")

        if 8000.0 <= symbol_rate <= 120000.0:
            self._bump(scores, evidence, proto, 0.12, "metering_symbol_rate")

        if 0.004 <= bw <= 0.25:
            self._bump(scores, evidence, proto, 0.10, "narrow_metering_width")

        if signal_type in {"periodic", "burst"}:
            self._bump(scores, evidence, proto, 0.08, f"signal_type:{signal_type}")

        if periodicity >= 0.55:
            self._bump(scores, evidence, proto, 0.10, "periodic_metering_pattern")

        if nearest_wmbus <= 0.08 and modulation in {"fsk", "fsk_like", "2fsk", "gfsk", "gfsk_like", "gmsk"} and periodicity >= 0.85:
            self._bump(scores, evidence, proto, 0.12, "exact_center_periodic_fsk")

        if 0.01 <= duty_cycle <= 0.30:
            self._bump(scores, evidence, proto, 0.08, "low_duty_meter_profile")
        elif periodicity >= 0.85 and duty_cycle >= 0.85:
            self._bump(scores, evidence, proto, 0.05, "high_persistence_periodic_meter_profile")

        if "wireless_mbus" in protocol_hint or "wmbus" in protocol_hint or "m-bus" in protocol_hint:
            self._bump(scores, evidence, proto, 0.18, f"protocol_hint:{protocol_hint}")

        if any(token in subghz_profile for token in {"wireless_mbus", "wmbus", "meter", "utility"}):
            self._bump(scores, evidence, proto, 0.12, f"subghz_profile:{subghz_profile}")

        if frame_structure == "chirp":
            self._penalize(scores, penalties, proto, 0.28, "chirp_frame_conflict")

        if (
            nearest_lora <= 0.18
            and nearest_wmbus > 0.08
            and "wireless_mbus" not in subghz_profile
            and "wmbus" not in protocol_hint
        ):
            self._penalize(scores, penalties, proto, 0.14, "exact_lora_center_competition")

        if modulation in {"lora", "lora_like", "css", "chirp", "chirp_spread_spectrum"}:
            self._penalize(scores, penalties, proto, 0.30, "chirp_modulation_conflict")

    def _score_subghz_ook(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        proto = "SUBGHZ_OOK"
        freq = obs["freq_mhz"]
        bw = obs["bandwidth_mhz"]
        band = obs["rf_band"]
        modulation = obs["modulation"]
        symbol_rate = obs["symbol_rate"]
        burst_ms = obs["burst_ms"]
        periodicity = obs["periodicity_score"]
        frame_structure = obs["frame_structure"]

        if band in {"subghz", "sub_ghz", "sub-ghz"}:
            self._bump(scores, evidence, proto, 0.10, "subghz_band")

        if self._nearest_distance(freq, self.SUBGHZ_COMMON) <= 2.5:
            self._bump(scores, evidence, proto, 0.12, "common_remote_band")

        if modulation in {"ook", "ask", "pulse_ook"}:
            self._bump(scores, evidence, proto, 0.36, f"modulation:{modulation}")

        if 0.02 <= bw <= 0.80:
            self._bump(scores, evidence, proto, 0.10, "narrow_remote_width")

        if 1000.0 <= symbol_rate <= 15000.0:
            self._bump(scores, evidence, proto, 0.14, "remote_symbol_rate")

        if 20.0 <= burst_ms <= 400.0:
            self._bump(scores, evidence, proto, 0.08, "button_press_burst_window")

        if periodicity >= 0.30:
            self._bump(scores, evidence, proto, 0.05, "repeat_pattern_present")

        if frame_structure in {"repeated_remote_frame", "button_press_train"}:
            self._bump(scores, evidence, proto, 0.08, f"frame_structure:{frame_structure}")

        if bw >= 2.0:
            self._penalize(scores, penalties, proto, 0.08, "too_wide_for_typical_ook_remote")

    # -------------------------------------------------------------------------
    # CONSISTENCY SHAPING
    # -------------------------------------------------------------------------

    def _apply_consistency_shaping(
        self,
        obs: Dict[str, Any],
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        penalties: Dict[str, List[str]],
    ) -> None:
        bw = obs["bandwidth_mhz"]
        modulation = obs["modulation"]
        ofdm = obs["ofdm_likelihood"]
        band = obs["rf_band"]

        if modulation in {"oqpsk", "oqpsk_like", "dsss_oqpsk_like"} and 1.0 <= bw <= 3.5:
            self._bump(scores, evidence, "IEEE_802.15.4_ZIGBEE", 0.06, "cross_feature_consistency:oqpsk_plus_narrowband")

        if modulation in {"gfsk", "gfsk_like"} and 0.7 <= bw <= 2.5 and band in {"2_4ghz", "ble"}:
            self._bump(scores, evidence, "BLE", 0.05, "cross_feature_consistency:gfsk_plus_2_4ghz")

        if ofdm >= 0.55 and bw >= 8.0:
            self._bump(scores, evidence, "WIFI", 0.06, "cross_feature_consistency:ofdm_plus_wideband")

        if modulation in {"ook", "ask", "pulse_ook"} and band in {"2_4ghz", "wifi", "ble", "zigbee"}:
            self._penalize(scores, penalties, "SUBGHZ_OOK", 0.10, "band_conflict_for_subghz_ook")

        if modulation in {"lora", "css", "chirp", "chirp_spread_spectrum"} and band in {"2_4ghz", "wifi", "ble", "zigbee"}:
            self._penalize(scores, penalties, "LORA", 0.10, "band_conflict_for_lora")
        if modulation in {"lora", "css", "chirp", "chirp_spread_spectrum"}:
            self._penalize(scores, penalties, "WIRELESS_MBUS", 0.10, "chirp_conflict_for_wmbus")

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    def _protocol_family(self, protocol: str) -> str:
        mapping = {
            "WIFI": "WIFI",
            "BLE": "BLE",
            "IEEE_802.15.4_ZIGBEE": "IEEE_802.15.4",
            "LORA": "LPWAN",
            "WIRELESS_MBUS": "METERING",
            "SUBGHZ_FSK": "SUBGHZ",
            "SUBGHZ_OOK": "SUBGHZ",
            "UNKNOWN_PROTOCOL": "UNKNOWN",
        }
        return mapping.get(protocol, "UNKNOWN")

    def _is_near_ble_data_channel(self, freq_mhz: float) -> bool:
        for center in range(2404, 2479, 2):
            if abs(freq_mhz - float(center)) <= 0.8:
                return True
        return False

    def _nearest_distance(self, value: float, refs: List[float]) -> float:
        if not refs:
            return 9999.0
        return min(abs(value - ref) for ref in refs)

    def _bump(
        self,
        scores: Dict[str, float],
        evidence: Dict[str, List[str]],
        proto: str,
        delta: float,
        reason: str,
    ) -> None:
        scores[proto] = max(0.0, min(1.0, scores.get(proto, 0.0) + delta))
        evidence.setdefault(proto, []).append(reason)

    def _penalize(
        self,
        scores: Dict[str, float],
        penalties: Dict[str, List[str]],
        proto: str,
        delta: float,
        reason: str,
    ) -> None:
        scores[proto] = max(0.0, min(1.0, scores.get(proto, 0.0) - delta))
        penalties.setdefault(proto, []).append(reason)

    def _first_present(self, primary: Dict[str, Any], secondary: Dict[str, Any], keys: List[str]) -> Any:
        for key in keys:
            if key in primary and primary[key] is not None:
                return primary[key]
        for key in keys:
            if key in secondary and secondary[key] is not None:
                return secondary[key]
        return None

    def _norm_token(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            if not value:
                return ""
            value = value[0]
        text = str(value).strip().lower()
        for ch in [" ", "-", "/", ".", ":", ";", ",", "[", "]", "(", ")", "'", '"']:
            text = text.replace(ch, "_")
        while "__" in text:
            text = text.replace("__", "_")
        return text.strip("_")

    def _norm_token_list(self, value: Any) -> List[str]:
        if value is None:
            return []

        items: List[Any]
        if isinstance(value, list):
            items = value
        else:
            text = str(value).strip()
            if text.startswith("[") and text.endswith("]"):
                inner = text[1:-1]
                items = [part.strip() for part in inner.split(",") if part.strip()]
            else:
                items = [text]

        out: List[str] = []
        seen = set()
        for item in items:
            token = self._norm_token(item)
            if token and token not in seen:
                seen.add(token)
                out.append(token)
        return out

    def _safe_float(self, value: Any, default: float) -> float:
        try:
            if value in (None, ""):
                return default
            if isinstance(value, list):
                value = value[0] if value else default
            return float(value)
        except Exception:
            return default

    def _safe_int(self, value: Any, default: Optional[int]) -> Optional[int]:
        try:
            if value in (None, ""):
                return default
            if isinstance(value, list):
                value = value[0] if value else default
            return int(float(value))
        except Exception:
            return default
