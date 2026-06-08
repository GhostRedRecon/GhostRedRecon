# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/protocol/protocol_engine.py
# VERSION:      v3.0.0 (PRODUCTION ORCHESTRATION + ROBUST MERGE + EXPLAINABLE EXPORTS)
# LAST UPDATED: 2026-03-15
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# ReconEngine / SignalEngine / Emitter Pipeline
#     ↓
# ProtocolEngine   <-- THIS FILE
#     ↓
# ProtocolSignatureEngine
#     ↓
# Deterministic protocol scoring
#     ↓
# Compatibility merge / result promotion / explainability shaping
#     ↓
# Signal storage / API / downstream identity inference
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# GhostRecon is a passive RF reconnaissance and red-team intelligence platform.
#
# This file is the production protocol orchestration layer that:
#   - receives upstream signal/emitter records
#   - normalizes orchestration behavior around protocol inference
#   - invokes ProtocolSignatureEngine
#   - merges results into a stable project-facing schema
#   - preserves explainability and ranked candidates
#   - remains backward-compatible with older pipeline consumers
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
#
# This file IS responsible for:
#   - protocol orchestration
#   - safe batch classification
#   - result merge policy
#   - backward-compatible field shaping
#   - protocol export normalization
#   - explainability retention
#
# This file is NOT responsible for:
#   - SDR lifecycle
#   - emitter tracking
#   - packet decoding
#   - vendor/product attribution
#   - physical fingerprinting
#   - device identity scoring
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. DO NOT BREAK EXISTING PIPELINES
#    Preserve legacy fields while exporting richer protocol intelligence.
#
# 2. ORCHESTRATION ONLY
#    Scoring belongs to ProtocolSignatureEngine.
#
# 3. SAFE MERGING
#    Never allow malformed records to crash the pipeline.
#
# 4. EXPLAINABILITY FIRST
#    Evidence, ambiguity, and ranked candidates must survive merge/export.
#
# 5. CONSERVATIVE PROMOTION
#    UNKNOWN is preferred over low-confidence false certainty.
#
# =============================================================================

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional


from .protocol_signature_engine import ProtocolSignatureEngine


logger = logging.getLogger(__name__)


class ProtocolEngine:
    """
    Production protocol orchestration layer.

    Main usage:
        engine = ProtocolEngine()
        enriched = engine.classify_emitters(emitters)

    Backward-compatible entrypoints:
        - classify()
        - classify_signal()
        - process()
        - run()
    """

    VERSION = "3.0.0"

    # Orchestration-level acceptance thresholds.
    # These are intentionally modest because the signature engine already
    # handles ambiguity and UNKNOWN fallback.
    MIN_ACCEPT_CONFIDENCE = 0.43

    def __init__(self) -> None:
        self.signature_engine = ProtocolSignatureEngine()

    # ---------------------------------------------------------------------
    # PRIMARY PUBLIC API
    # ---------------------------------------------------------------------

    def classify_emitters(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        for emitter in emitters or []:
            try:
                results.append(self.classify_emitter(emitter))
            except Exception as exc:
                logger.warning("ProtocolEngine emitter classification failure: %s", exc)
                safe = dict(emitter) if isinstance(emitter, dict) else {"raw_emitter": emitter}
                safe.update(self._unknown_result(reason="exception"))
                safe["protocol_engine_version"] = self.VERSION
                results.append(safe)

        return results

    def classify_emitter(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(emitter, dict):
            out = {"raw_emitter": emitter}
            out.update(self._unknown_result(reason="non_dict_emitter"))
            out["protocol_engine_version"] = self.VERSION
            return out

        working = dict(emitter)
        preexisting = self._extract_preexisting_protocol_state(working)

        signature_result = self.signature_engine.classify(working)
        merged = self._merge_protocol_result(working, preexisting, signature_result)

        self._apply_backward_compatible_fields(merged)
        self._apply_protocol_aliases(merged)
        self._apply_device_hints(merged)
        self._apply_export_shape(merged)

        merged["protocol_engine_version"] = self.VERSION
        return merged

    # ---------------------------------------------------------------------
    # BACKWARD-COMPATIBILITY ENTRYPOINTS
    # ---------------------------------------------------------------------

    def classify(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        return self.classify_emitter(emitter)

    def classify_signal(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        return self.classify_emitter(signal)

    def process(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.classify_emitters(emitters)

    def run(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.classify_emitters(emitters)

    # ---------------------------------------------------------------------
    # MERGE POLICY
    # ---------------------------------------------------------------------

    def _extract_preexisting_protocol_state(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "protocol": self._norm_protocol(record.get("protocol")),
            "protocol_guess": self._norm_protocol(record.get("protocol_guess")),
            "protocol_family": self._norm_family(record.get("protocol_family")),
            "protocol_confidence": self._safe_float(record.get("protocol_confidence"), 0.0),
            "confidence": self._safe_float(record.get("confidence"), 0.0),
            "signal_confidence": self._safe_float(record.get("signal_confidence"), 0.0),
        }

    def _merge_protocol_result(
        self,
        working: Dict[str, Any],
        preexisting: Dict[str, Any],
        signature_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        merged = dict(working)

        # Always preserve raw signature-engine exports.
        for key, value in signature_result.items():
            merged[key] = value

        sig_protocol = self._norm_protocol(signature_result.get("protocol_signature"))
        sig_family = self._norm_family(signature_result.get("protocol_family"))
        sig_conf = self._safe_float(signature_result.get("protocol_confidence"), 0.0)

        old_protocol = preexisting.get("protocol", "UNKNOWN_PROTOCOL")
        old_conf = max(
            preexisting.get("protocol_confidence", 0.0),
            preexisting.get("confidence", 0.0),
            preexisting.get("signal_confidence", 0.0),
        )

        # Final orchestration decision:
        # Prefer signature result if it is non-unknown and above threshold.
        # Otherwise preserve a meaningful existing protocol if it was already stronger.
        final_protocol = sig_protocol
        final_family = sig_family
        final_conf = sig_conf

        if sig_protocol == "UNKNOWN_PROTOCOL" or sig_conf < self.MIN_ACCEPT_CONFIDENCE:
            if old_protocol != "UNKNOWN_PROTOCOL" and old_conf >= sig_conf and old_conf >= self.MIN_ACCEPT_CONFIDENCE:
                final_protocol = old_protocol
                final_family = preexisting.get("protocol_family", "UNKNOWN")
                final_conf = old_conf

                merged.setdefault("protocol_merge_notes", [])
                merged["protocol_merge_notes"].append("retained_preexisting_protocol_due_to_stronger_existing_confidence")
            else:
                final_protocol = "UNKNOWN_PROTOCOL"
                final_family = "UNKNOWN"
                final_conf = max(sig_conf, 0.0)

                merged.setdefault("protocol_merge_notes", [])
                merged["protocol_merge_notes"].append("signature_result_not_strong_enough_for_protocol_promotion")
        else:
            merged.setdefault("protocol_merge_notes", [])
            merged["protocol_merge_notes"].append("signature_result_promoted_to_final_protocol")

        merged["protocol_signature"] = final_protocol
        merged["protocol_guess"] = final_protocol
        merged["protocol_family"] = final_family
        merged["protocol_confidence"] = round(final_conf, 3)

        # Ensure ambiguity object always exists
        if not isinstance(merged.get("protocol_ambiguity"), dict):
            merged["protocol_ambiguity"] = {
                "ambiguous": final_protocol == "UNKNOWN_PROTOCOL",
                "reason": "missing_ambiguity_payload",
                "winner_margin": 0.0,
                "runner_up": None,
            }

        # Ensure ranked candidates always exist
        if not isinstance(merged.get("ranked_protocol_candidates"), list):
            merged["ranked_protocol_candidates"] = self._build_ranked_candidates_from_score_map(
                merged.get("protocol_score_map")
            )

        # Ensure evidence always exists
        if not isinstance(merged.get("protocol_evidence"), list):
            merged["protocol_evidence"] = []

        return merged

    # ---------------------------------------------------------------------
    # INTERNAL SHAPING
    # ---------------------------------------------------------------------

    def _apply_backward_compatible_fields(self, record: Dict[str, Any]) -> None:
        protocol = self._norm_protocol(record.get("protocol_signature"))
        confidence = self._safe_float(record.get("protocol_confidence"), 0.0)
        family = self._norm_family(record.get("protocol_family"))

        record["protocol"] = protocol
        record["protocol_guess"] = protocol
        record["protocol_signature"] = protocol
        record["protocol_family"] = family
        record["protocol_confidence"] = round(confidence, 3)

        # Legacy pipeline confidence behavior:
        # do not clobber a stronger existing confidence, but do ensure a value exists
        existing_conf = self._safe_float(record.get("confidence"), 0.0)
        if existing_conf <= 0.0:
            record["confidence"] = round(confidence, 3)

        existing_signal_conf = self._safe_float(record.get("signal_confidence"), 0.0)
        if existing_signal_conf <= 0.0:
            record["signal_confidence"] = round(confidence, 3)

        if "device_confidence" not in record or record.get("device_confidence") is None:
            record["device_confidence"] = 0.0

    def _apply_protocol_aliases(self, record: Dict[str, Any]) -> None:
        protocol = self._norm_protocol(record.get("protocol_signature"))

        alias_map = {
            "WIFI": "WIFI",
            "BLE": "BLE",
            "IEEE_802.15.4_ZIGBEE": "IEEE_802.15.4_ZIGBEE",
            "LORA": "LORA",
            "SUBGHZ_FSK": "SUBGHZ_FSK",
            "SUBGHZ_OOK": "SUBGHZ_OOK",
            "UNKNOWN_PROTOCOL": "UNKNOWN_PROTOCOL",
        }

        family_map = {
            "WIFI": "WIFI",
            "BLE": "BLE",
            "IEEE_802.15.4_ZIGBEE": "IEEE_802.15.4",
            "LORA": "LPWAN",
            "SUBGHZ_FSK": "SUBGHZ",
            "SUBGHZ_OOK": "SUBGHZ",
            "UNKNOWN_PROTOCOL": "UNKNOWN",
        }

        canonical = alias_map.get(protocol, "UNKNOWN_PROTOCOL")
        record["protocol"] = canonical
        record["protocol_signature"] = canonical
        record["protocol_guess"] = canonical
        record["protocol_family"] = family_map.get(canonical, "UNKNOWN")

    def _apply_device_hints(self, record: Dict[str, Any]) -> None:
        protocol = self._norm_protocol(record.get("protocol"))

        if protocol == "WIFI":
            record.setdefault("device_category", "Wireless Network Device")
            record.setdefault("device_type", "WiFi Device")
        elif protocol == "BLE":
            record.setdefault("device_category", "Short-Range Wireless Device")
            record.setdefault("device_type", "BLE Device")
        elif protocol == "IEEE_802.15.4_ZIGBEE":
            record.setdefault("device_category", "IoT Mesh Device")
            record.setdefault("device_type", "Zigbee Device")
        elif protocol in {"SUBGHZ_FSK", "SUBGHZ_OOK"}:
            record.setdefault("device_category", "Sub-GHz RF Device")
            record.setdefault("device_type", "Sub-GHz Device")
        elif protocol == "LORA":
            record.setdefault("device_category", "LPWAN Device")
            record.setdefault("device_type", "LoRa Device")
            role_hint, role_conf = self._infer_lora_role_hint(record)
            record.setdefault("device_role_hint", role_hint)
            record.setdefault("lora_role_hint", role_hint)
            record.setdefault("device_role_confidence", role_conf)
            record.setdefault("lora_role_confidence", role_conf)
        else:
            record.setdefault("device_category", None)
            record.setdefault("device_type", None)

    def _apply_export_shape(self, record: Dict[str, Any]) -> None:
        # Stable explainability exports for APIs, validators, and downstream layers.
        record.setdefault("protocol_candidates", [])
        record.setdefault("ranked_protocol_candidates", [])
        record.setdefault("protocol_evidence", [])
        record.setdefault("protocol_score_map", {})
        record.setdefault("protocol_penalty_map", {})
        record.setdefault("protocol_merge_notes", [])

        if "explanation" not in record or not isinstance(record.get("explanation"), list):
            record["explanation"] = []

        if record.get("protocol") != "UNKNOWN_PROTOCOL":
            record["explanation"].append(
                f"protocol_engine_selected:{record.get('protocol')}@{record.get('protocol_confidence')}"
            )
        else:
            reason = None
            ambiguity = record.get("protocol_ambiguity", {})
            if isinstance(ambiguity, dict):
                reason = ambiguity.get("reason")
            if reason:
                record["explanation"].append(f"protocol_unknown_reason:{reason}")

        # Flatten common project-facing aliases for older consumers.
        record["rf_protocol"] = record.get("protocol", "UNKNOWN_PROTOCOL")
        record["rf_protocol_family"] = record.get("protocol_family", "UNKNOWN")
        record["rf_protocol_confidence"] = self._safe_float(record.get("protocol_confidence"), 0.0)

    # ---------------------------------------------------------------------
    # FALLBACKS / HELPERS
    # ---------------------------------------------------------------------

    def _build_ranked_candidates_from_score_map(self, score_map: Any) -> List[Dict[str, Any]]:
        if not isinstance(score_map, dict):
            return []

        ranked = sorted(
            [
                (self._norm_protocol(k), self._safe_float(v, 0.0))
                for k, v in score_map.items()
                if self._norm_protocol(k)
            ],
            key=lambda x: x[1],
            reverse=True,
        )

        out: List[Dict[str, Any]] = []
        for name, score in ranked[:5]:
            if score <= 0.0:
                continue
            out.append(
                {
                    "protocol": name,
                    "family": self._family_from_protocol(name),
                    "score": round(score, 3),
                    "evidence": [],
                    "penalties": [],
                }
            )
        return out

    def _infer_lora_role_hint(self, record: Dict[str, Any]) -> tuple[str, float]:
        power = self._safe_float(
            record.get("power_db", record.get("rf_power_db")),
            -120.0,
        )
        hit_count = self._safe_float(
            record.get("hit_count", record.get("rf_emitter_hits")),
            0.0,
        )
        periodicity = self._safe_float(
            record.get("periodicity", record.get("rf_burst_periodicity")),
            0.0,
        )
        bandwidth_class = str(record.get("bandwidth_class") or "").lower()
        temporal_profile = str(record.get("rf_temporal_profile") or "").lower()

        if hit_count >= 6 and periodicity >= 0.5 and power >= -75:
            return "gateway", 0.72
        if "narrow" in bandwidth_class or temporal_profile in {"periodic", "bursty"} or power < -75:
            return "end_device", 0.64
        return "unknown", 0.25

    def _unknown_result(self, reason: str) -> Dict[str, Any]:
        return {
            "protocol_signature": "UNKNOWN_PROTOCOL",
            "protocol_guess": "UNKNOWN_PROTOCOL",
            "protocol_family": "UNKNOWN",
            "protocol_confidence": 0.0,
            "protocol_candidates": [],
            "ranked_protocol_candidates": [],
            "protocol_evidence": [reason],
            "protocol_score_map": {},
            "protocol_penalty_map": {},
            "protocol_merge_notes": [f"unknown:{reason}"],
            "protocol_ambiguity": {
                "ambiguous": True,
                "reason": reason,
                "winner_margin": 0.0,
                "runner_up": None,
            },
            "protocol": "UNKNOWN_PROTOCOL",
            "rf_protocol": "UNKNOWN_PROTOCOL",
            "rf_protocol_family": "UNKNOWN",
            "rf_protocol_confidence": 0.0,
        }

    def _norm_protocol(self, value: Any) -> str:
        if value is None:
            return "UNKNOWN_PROTOCOL"
        text = str(value).strip().upper()
        if not text:
            return "UNKNOWN_PROTOCOL"
        aliases = {
            "UNKNOWN": "UNKNOWN_PROTOCOL",
            "UNKNOWN_PROTOCOL": "UNKNOWN_PROTOCOL",
            "WIFI": "WIFI",
            "WI-FI": "WIFI",
            "BLE": "BLE",
            "BLUETOOTH_LE": "BLE",
            "IEEE_802.15.4_ZIGBEE": "IEEE_802.15.4_ZIGBEE",
            "ZIGBEE": "IEEE_802.15.4_ZIGBEE",
            "IEEE_802154_ZIGBEE": "IEEE_802.15.4_ZIGBEE",
            "LORA": "LORA",
            "SUBGHZ_FSK": "SUBGHZ_FSK",
            "SUB_GHZ_FSK": "SUBGHZ_FSK",
            "SUBGHZ_OOK": "SUBGHZ_OOK",
            "SUB_GHZ_OOK": "SUBGHZ_OOK",
        }
        return aliases.get(text, text if text else "UNKNOWN_PROTOCOL")

    def _norm_family(self, value: Any) -> str:
        if value is None:
            return "UNKNOWN"
        text = str(value).strip().upper()
        if not text:
            return "UNKNOWN"
        aliases = {
            "UNKNOWN_PROTOCOL": "UNKNOWN",
            "UNKNOWN": "UNKNOWN",
            "WIFI": "WIFI",
            "BLE": "BLE",
            "IEEE_802.15.4": "IEEE_802.15.4",
            "IEEE_802154": "IEEE_802.15.4",
            "LPWAN": "LPWAN",
            "SUBGHZ": "SUBGHZ",
            "SUB-GHZ": "SUBGHZ",
        }
        return aliases.get(text, text)

    def _family_from_protocol(self, protocol: str) -> str:
        mapping = {
            "WIFI": "WIFI",
            "BLE": "BLE",
            "IEEE_802.15.4_ZIGBEE": "IEEE_802.15.4",
            "LORA": "LPWAN",
            "SUBGHZ_FSK": "SUBGHZ",
            "SUBGHZ_OOK": "SUBGHZ",
            "UNKNOWN_PROTOCOL": "UNKNOWN",
        }
        return mapping.get(protocol, "UNKNOWN")

    def _safe_float(self, value: Any, default: float) -> float:
        try:
            if value in (None, ""):
                return default
            if isinstance(value, list):
                value = value[0] if value else default
            return float(value)
        except Exception:
            return default
