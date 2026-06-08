from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List


class FalsePositiveSuppressionEngine:
    INFRA_HINTS = ("movistar", "vodafone", "orange", "tp-link", "tplink", "asus", "netgear", "router", "ap")
    NON_DRONE_HINTS = INFRA_HINTS + ("iphone", "android", "samsung", "printer", "tv", "chromecast", "laptop", "windows", "galaxy")

    def evaluate(self, item: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        ssid = str(item.get("ssid") or item.get("label") or "").strip().lower()
        vendor = str(item.get("vendor") or item.get("manufacturer") or "").strip().lower()
        packet_count = int(item.get("packet_count") or 0)
        penalties: List[Dict[str, Any]] = []
        if ssid in set(baseline.get("common_ssids") or []):
            penalties.append({"name": "known_consumer_wifi_ap_suppression", "value": -18, "reason": "SSID is part of the local baseline."})
        if any(token in ssid for token in self.INFRA_HINTS) or any(token in vendor for token in self.INFRA_HINTS):
            penalties.append({"name": "stationary_ap_persistence_suppression", "value": -15, "reason": "Observed identity resembles infrastructure Wi-Fi."})
        if any(token in ssid for token in self.NON_DRONE_HINTS) or any(token in vendor for token in self.NON_DRONE_HINTS):
            penalties.append({"name": "non_uav_identity_suppression", "value": -20, "reason": "Observed identity resembles a non-UAV device."})
        if packet_count <= 1:
            penalties.append({"name": "one_off_sighting_decay", "value": -8, "reason": "Only a one-off sighting was retained."})
        return {
            "penalties": penalties,
            "total_penalty": sum(int(entry["value"]) for entry in penalties),
        }


class ProofTierEngine:
    def assign(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if features.get("decoder_backed") and features.get("multi_sensor") and features.get("replayable") and features.get("raw_evidence_complete"):
            tier = 4
            label = "Audit-grade Confirmed"
        elif features.get("decoder_backed") and features.get("multi_sensor"):
            tier = 3
            label = "Multi-sensor Corroborated"
        elif features.get("decoder_backed"):
            tier = 2
            label = "Decoder-backed Candidate"
        elif features.get("recurrence_count", 0) >= 3 or features.get("temporal_stability", 0) >= 0.55:
            tier = 1
            label = "Multi-observation Heuristic"
        else:
            tier = 0
            label = "Heuristic Lead"
        return {"tier": tier, "label": label}


class ConfidenceScoringEngine:
    WEIGHTS = {
        "wifi_signature_evidence": 14,
        "vendor_oui_evidence": 8,
        "remote_id_evidence": 18,
        "dji_decoder_profile_evidence": 16,
        "sdr_peak_strength": 10,
        "recurrence": 8,
        "temporal_stability": 8,
        "cross_band_consistency": 6,
        "cross_sensor_corroboration": 8,
        "baseline_anomaly_strength": 4,
    }

    def score(self, features: Dict[str, Any], suppression: Dict[str, Any], proof: Dict[str, Any]) -> Dict[str, Any]:
        components = {
            "wifi_signature_evidence": min(self.WEIGHTS["wifi_signature_evidence"], max(0, int(features.get("wifi_signature_score", 0)))),
            "vendor_oui_evidence": min(self.WEIGHTS["vendor_oui_evidence"], max(0, int(features.get("vendor_score", 0)))),
            "remote_id_evidence": min(self.WEIGHTS["remote_id_evidence"], max(0, int(features.get("remote_id_score", 0)))),
            "dji_decoder_profile_evidence": min(self.WEIGHTS["dji_decoder_profile_evidence"], max(0, int(features.get("dji_score", 0)))),
            "sdr_peak_strength": min(self.WEIGHTS["sdr_peak_strength"], max(0, int(features.get("sdr_score", 0)))),
            "recurrence": min(self.WEIGHTS["recurrence"], max(0, int(features.get("recurrence_score", 0)))),
            "temporal_stability": min(self.WEIGHTS["temporal_stability"], max(0, int(features.get("stability_score", 0)))),
            "cross_band_consistency": min(self.WEIGHTS["cross_band_consistency"], max(0, int(features.get("band_consistency_score", 0)))),
            "cross_sensor_corroboration": min(self.WEIGHTS["cross_sensor_corroboration"], max(0, int(features.get("sensor_score", 0)))),
            "baseline_anomaly_strength": min(self.WEIGHTS["baseline_anomaly_strength"], max(0, int(features.get("baseline_anomaly_score", 0)))),
        }
        base_score = sum(components.values())
        proof_bonus = {0: 0, 1: 6, 2: 12, 3: 18, 4: 24}.get(int(proof.get("tier", 0)), 0)
        total = max(0, min(100, base_score + proof_bonus + int(suppression.get("total_penalty") or 0)))
        rationale = list(features.get("rationale") or [])
        rationale.extend(entry["reason"] for entry in suppression.get("penalties") or [])
        if int(proof.get("tier", 0)) >= 2:
            rationale.append(f"Proof tier {proof['tier']} retained via decoder-backed evidence.")
        label = "low"
        if total >= 85:
            label = "very high"
        elif total >= 70:
            label = "high"
        elif total >= 50:
            label = "medium"
        return {"score": total, "label": label, "components": components, "rationale": rationale}


class DisruptionSusceptibilityEngine:
    def score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if not features.get("enough_audit_evidence"):
            return {"label": "Unknown", "rationale": ["insufficient data"]}
        risk = 0
        rationale: List[str] = []
        if not features.get("multi_band"):
            risk += 2
            rationale.append("single-band only")
        if float(features.get("signal_margin_db", 0.0)) < 10.0:
            risk += 1
            rationale.append("weak margin over noise floor")
        if float(features.get("dropout_ratio", 0.0)) >= 0.18:
            risk += 1
            rationale.append("frequent burst loss observed")
        if not features.get("fallback_observed"):
            risk += 1
            rationale.append("fallback path not observed")
        label = "Very Low"
        if risk >= 4:
            label = "High"
        elif risk == 3:
            label = "Moderate"
        elif risk == 2:
            label = "Low"
        return {"label": label, "rationale": rationale or ["link diversity observed"]}


class TargetFusionEngine:
    def fuse(self, detections: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        buckets: Dict[str, Dict[str, Any]] = {}
        for item in detections:
            key = str(item.get("identifier") or item.get("target_id") or "")
            if not key:
                key = str(item.get("label") or "")
            existing = buckets.get(key)
            if not existing:
                buckets[key] = dict(item)
                buckets[key]["evidence"] = list(item.get("evidence") or [])
                buckets[key]["evidence_sensors"] = list(dict.fromkeys(item.get("evidence_sensors") or []))
                buckets[key]["reasons"] = list(dict.fromkeys(item.get("reasons") or []))
                continue
            existing["confidence"] = max(int(existing.get("confidence") or 0), int(item.get("confidence") or 0))
            existing["classification"] = item.get("classification") if int(item.get("confidence") or 0) >= int(existing.get("confidence") or 0) else existing.get("classification")
            existing["manufacturer"] = existing.get("manufacturer") or item.get("manufacturer")
            existing["model_family"] = existing.get("model_family") or item.get("model_family")
            existing["band"] = existing.get("band") or item.get("band")
            existing["channel"] = existing.get("channel") or item.get("channel")
            existing["evidence"].extend(item.get("evidence") or [])
            existing["evidence_sensors"] = list(dict.fromkeys([*(existing.get("evidence_sensors") or []), *(item.get("evidence_sensors") or [])]))
            existing["reasons"] = list(dict.fromkeys([*(existing.get("reasons") or []), *(item.get("reasons") or [])]))
        return list(buckets.values())


class SwarmGroupingEngine:
    def group(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        family_counts: Dict[str, int] = defaultdict(int)
        for item in detections:
            family = str(item.get("family_label") or item.get("manufacturer") or "Unknown Family")
            family_counts[family] += 1
        enriched: List[Dict[str, Any]] = []
        for item in detections:
            family = str(item.get("family_label") or item.get("manufacturer") or "Unknown Family")
            count = family_counts[family]
            clone = dict(item)
            clone["swarm_label"] = family if count > 1 else "Single Target"
            clone["swarm_count"] = count
            clone["swarm_role"] = "Swarm Candidate" if count > 1 else "Independent Target"
            clone["group_confidence"] = "medium" if count > 1 else "low"
            clone["ambiguity_flag"] = count > 2 and family.lower().startswith("unknown")
            enriched.append(clone)
        return enriched
