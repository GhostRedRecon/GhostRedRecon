from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from backend.integrations.ble_normalizer import normalize_observation
from backend.integrations.classification_engine import CLASSIFICATION_LABELS, classify_cluster
from backend.integrations.confidence_engine import compute_confidence


class BLEIntelligenceEngine:
    DEFAULT_RULE_WEIGHTS = {
        "company_id_match": 30,
        "uuid_match": 30,
        "manufacturer_match": 30,
        "behavior_match": 10,
    }

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.database = self._load_database()
        self.devices = list(self.database.get("devices") or [])

    def _load_database(self) -> Dict[str, Any]:
        if not self.db_path.exists():
            return {"metadata": {}, "devices": []}
        try:
            payload = json.loads(self.db_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload.setdefault("metadata", {})
                payload.setdefault("devices", [])
                return payload
        except Exception:
            pass
        return {"metadata": {}, "devices": []}

    def database_summary(self) -> Dict[str, Any]:
        category_counts: Dict[str, int] = {}
        classification_counts: Dict[str, int] = {}
        for device in self.devices:
            category = str(device.get("category") or "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1
            classification_type = str(device.get("classification_type") or "Unknown")
            classification_counts[classification_type] = classification_counts.get(classification_type, 0) + 1
        return {
            "loaded": bool(self.devices),
            "device_count": len(self.devices),
            "categories": category_counts,
            "classified_types": classification_counts,
            "version": self.database.get("metadata", {}).get("version") or "",
        }

    def _normalize_company_id(self, value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            if isinstance(value, str):
                text = value.strip().lower()
                if text.startswith("0x"):
                    return int(text, 16)
                return int(text)
            return int(value)
        except Exception:
            return None

    def _normalize_uuid(self, value: Any) -> str:
        return str(value or "").strip().lower().replace("-", "")

    def _normalize_prefix(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _normalize_name_tokens(self, values: Any) -> List[str]:
        normalized: List[str] = []
        if isinstance(values, str):
            values = [values]
        for value in (values or []):
            token = str(value or "").strip().lower()
            if token:
                normalized.append(token)
        return normalized

    def _normalize_bool(self, value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "1", "yes"}:
            return True
        if text in {"false", "0", "no"}:
            return False
        return None

    def _level(self, score: int) -> str:
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    def _quick_rule_classification(self, observation: Dict[str, Any]) -> Dict[str, Any] | None:
        company_id = self._normalize_company_id(observation.get("company_id"))
        service_uuids = {self._normalize_uuid(item) for item in (observation.get("service_uuids") or []) if str(item).strip()}
        address_type = str(observation.get("address_type") or "").strip().lower()
        connectable = self._normalize_bool(observation.get("connectable"))
        interval_ms = observation.get("advertising_interval_ms")
        manufacturer_prefix = self._normalize_prefix(observation.get("manufacturer_data_prefix"))
        confidence = 0
        reasons: List[str] = []

        if {"0201", "0303"}.issubset(service_uuids) and address_type == "public" and connectable is True:
            confidence += 70
            reasons.extend(["uuid:0201", "uuid:0303", "public_mac", "connectable"])
            return {
                "matched": True,
                "device_name": "Android-like Device Cluster",
                "vendor": "Unknown",
                "model": "",
                "category": "smartphone",
                "type": "phone",
                "classification_type": "Mobile",
                "protocol": "BLE",
                "confidence": confidence,
                "level": self._level(confidence),
                "classification": f"{self._level(confidence)}_CONFIDENCE",
                "pairing": "Likely Just Works",
                "notes": "Quick rule match for public, connectable Android-like BLE advertisement family.",
                "behavior_profile": {
                    "burst": int(observation.get("observation_count") or 0) <= 1,
                    "interval_stable": interval_ms is not None,
                    "connect_attempts": 0,
                },
                "risk_profile": "medium",
                "match_reasons": reasons,
                "source": "quick_rule",
                "ui_tone": "cyan",
                "icon": "📱",
            }

        if company_id == 76 and address_type == "random":
            confidence += 60
            reasons.extend(["company_id:0x004c", "random_mac"])
            if int(observation.get("observation_count") or 0) <= 1:
                confidence += 10
                reasons.append("burst_advertising")
            return {
                "matched": True,
                "device_name": "Apple Mobile / Ecosystem Device",
                "vendor": "Apple",
                "model": "",
                "category": "smartphone",
                "type": "phone",
                "classification_type": "Mobile",
                "protocol": "BLE",
                "confidence": confidence,
                "level": self._level(confidence),
                "classification": f"{self._level(confidence)}_CONFIDENCE",
                "pairing": "Ecosystem pairing",
                "notes": "Quick rule match for Apple company ID with privacy-randomized address behavior.",
                "behavior_profile": {
                    "burst": int(observation.get("observation_count") or 0) <= 1,
                    "interval_stable": interval_ms is not None,
                    "connect_attempts": 0,
                },
                "risk_profile": "low",
                "match_reasons": reasons,
                "source": "quick_rule",
                "ui_tone": "cyan",
                "icon": "📱",
            }

        if connectable is False and not service_uuids:
            confidence += 55
            reasons.extend(["non_connectable", "no_services"])
            if interval_ms is not None:
                confidence += 10
                reasons.append("stable_interval")
            return {
                "matched": True,
                "device_name": "BLE Beacon",
                "vendor": "Unknown",
                "model": "",
                "category": "beacon",
                "type": "broadcast",
                "classification_type": "Beacon",
                "protocol": "BLE",
                "confidence": confidence,
                "level": self._level(confidence),
                "classification": f"{self._level(confidence)}_CONFIDENCE",
                "pairing": "",
                "notes": "Quick rule match for broadcast-only BLE beacon behavior.",
                "behavior_profile": {
                    "burst": int(observation.get("observation_count") or 0) <= 1,
                    "interval_stable": interval_ms is not None,
                    "connect_attempts": 0,
                },
                "risk_profile": "low",
                "match_reasons": reasons,
                "source": "quick_rule",
                "ui_tone": "amber",
                "icon": "📡",
            }

        if connectable is True and company_id is None and not manufacturer_prefix:
            confidence += 50
            reasons.extend(["connectable", "unknown_vendor"])
            return {
                "matched": True,
                "device_name": "IoT Candidate",
                "vendor": "Unknown",
                "model": "",
                "category": "iot_candidate",
                "type": "smart_device",
                "classification_type": "IoT",
                "protocol": "BLE",
                "confidence": confidence,
                "level": self._level(confidence),
                "classification": f"{self._level(confidence)}_CONFIDENCE",
                "pairing": "Unknown",
                "notes": "Quick rule match for connectable BLE device with weak vendor identity.",
                "behavior_profile": {
                    "burst": int(observation.get("observation_count") or 0) <= 1,
                    "interval_stable": interval_ms is not None,
                    "connect_attempts": 0,
                },
                "risk_profile": "high",
                "match_reasons": reasons,
                "source": "quick_rule",
                "ui_tone": "green",
                "icon": "🔌",
            }
        return None

    def _ui_tone(self, classified_type: str, risk_profile: str) -> str:
        if risk_profile == "high":
            return "red"
        if classified_type == "Mobile":
            return "cyan"
        if classified_type == "IoT":
            return "green"
        if classified_type == "Beacon":
            return "amber"
        return "neutral"

    def _icon(self, category: str, classified_type: str) -> str:
        lowered = str(category or "").lower()
        if lowered in {"smartwatch", "fitness", "health tracker"}:
            return "⌚"
        if lowered in {"earbuds", "earphones", "speaker", "audio"}:
            return "🎧"
        if lowered in {"bulb", "sensor", "lock", "scale"}:
            return "💡"
        if lowered in {"gaming", "controller"}:
            return "🎮"
        if classified_type == "Mobile":
            return "📱"
        if classified_type == "Beacon":
            return "📡"
        if classified_type == "IoT":
            return "🔌"
        return "❓"

    def _behavior_match(self, observation: Dict[str, Any], fingerprint: Dict[str, Any]) -> tuple[bool, List[str]]:
        behavior = fingerprint.get("behavior") if isinstance(fingerprint.get("behavior"), dict) else {}
        reasons: List[str] = []
        matched = False
        observed_interval = observation.get("advertising_interval_ms")
        observed_rssi = observation.get("avg_rssi")
        expected_interval = behavior.get("interval_ms_range") if isinstance(behavior.get("interval_ms_range"), list) else []
        expected_rssi = behavior.get("rssi_range") if isinstance(behavior.get("rssi_range"), list) else []
        connectable_expected = self._normalize_bool((fingerprint.get("adv_patterns") or {}).get("connectable"))
        connectable_observed = self._normalize_bool(observation.get("connectable"))
        address_types = [str(item).strip().lower() for item in (fingerprint.get("address_type") or []) if str(item).strip()]
        observed_address_type = str(observation.get("address_type") or "").strip().lower()

        if len(expected_interval) == 2 and observed_interval is not None:
            try:
                low, high = float(expected_interval[0]), float(expected_interval[1])
                value = float(observed_interval)
                if low <= value <= high:
                    matched = True
                    reasons.append(f"interval:{int(value)}ms")
            except Exception:
                pass
        if len(expected_rssi) == 2 and observed_rssi is not None:
            try:
                low, high = float(expected_rssi[0]), float(expected_rssi[1])
                value = float(observed_rssi)
                if low <= value <= high:
                    matched = True
                    reasons.append(f"rssi:{int(value)}dBm")
            except Exception:
                pass
        if connectable_expected is not None and connectable_observed is not None and connectable_expected == connectable_observed:
            matched = True
            reasons.append("connectable_match")
        if address_types and observed_address_type:
            for expected in address_types:
                if expected in {"rotating", "random"} and observed_address_type == "random":
                    matched = True
                    reasons.append("address_type_random")
                    break
                if expected == observed_address_type:
                    matched = True
                    reasons.append(f"address_type:{observed_address_type}")
                    break
        return matched, reasons

    def classify_device(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        normalized = normalize_observation(observation)
        cluster_size = max(1, int(observation.get("cluster_size") or normalized.get("observation_count") or 1))
        provisional_cluster = [dict(normalized) for _ in range(cluster_size)]
        provisional_label = classify_cluster(provisional_cluster)
        provisional_confidence = compute_confidence(provisional_cluster)
        provisional_meta = CLASSIFICATION_LABELS.get(provisional_label, CLASSIFICATION_LABELS["unknown_candidate"])

        quick_rule = self._quick_rule_classification(observation)
        company_id = self._normalize_company_id(normalized.get("company_id"))
        manufacturer_prefix = self._normalize_prefix(normalized.get("manufacturer_prefix"))
        service_uuids = {self._normalize_uuid(item) for item in (normalized.get("service_uuids") or []) if str(item).strip()}
        name = str(normalized.get("name") or "").strip().lower()
        connectable = self._normalize_bool(normalized.get("connectable"))

        best_match: Dict[str, Any] | None = None
        best_score = -1
        best_reasons: List[str] = []

        for fingerprint in self.devices:
            weights = dict(self.DEFAULT_RULE_WEIGHTS)
            weights.update(fingerprint.get("confidence_rules") or {})
            score = 0
            reasons: List[str] = []
            anchor_hits = 0

            fingerprint_company = self._normalize_company_id(fingerprint.get("company_id"))
            if fingerprint_company is not None and company_id is not None and fingerprint_company == company_id:
                score += int(weights.get("company_id_match") or 0)
                reasons.append(f"company_id:0x{company_id:04x}")
                anchor_hits += 1

            adv_patterns = fingerprint.get("adv_patterns") if isinstance(fingerprint.get("adv_patterns"), dict) else {}
            fingerprint_prefix = self._normalize_prefix(adv_patterns.get("manufacturer_data_prefix"))
            if fingerprint_prefix and manufacturer_prefix.startswith(fingerprint_prefix):
                score += int(weights.get("manufacturer_match") or 0)
                reasons.append(f"manufacturer_prefix:{fingerprint_prefix}")
                anchor_hits += 1

            fingerprint_uuids = {self._normalize_uuid(item) for item in (adv_patterns.get("service_uuids") or []) if str(item).strip()}
            uuid_overlap = sorted(service_uuids.intersection(fingerprint_uuids))
            if uuid_overlap:
                score += int(weights.get("uuid_match") or 0)
                reasons.append(f"uuid:{uuid_overlap[0]}")
                anchor_hits += 1

            if name:
                name_fields = [
                    str(fingerprint.get("name") or "").lower(),
                    str(fingerprint.get("model") or "").lower(),
                ]
                if any(field and field in name for field in name_fields):
                    score += 15
                    reasons.append("name_match")
                    anchor_hits += 1
                alias_tokens = self._normalize_name_tokens((adv_patterns.get("name_contains") or []))
                if any(token and token in name for token in alias_tokens):
                    score += 35
                    reasons.append("name_alias_match")
                    anchor_hits += 1

            if connectable is not None:
                expected_connectable = self._normalize_bool(adv_patterns.get("connectable"))
                if expected_connectable is not None and expected_connectable == connectable:
                    score += 5
                    reasons.append("connectable_profile")

            behavior_matched, behavior_reasons = self._behavior_match(observation, fingerprint)
            if behavior_matched:
                score += int(weights.get("behavior_match") or 0)
                reasons.extend(behavior_reasons)

            if anchor_hits == 0:
                continue

            if score > best_score:
                best_match = fingerprint
                best_score = score
                best_reasons = reasons

        level = self._level(max(best_score, 0))
        if quick_rule:
            quick_rule["confidence"] = max(int(quick_rule.get("confidence") or 0), provisional_confidence)
            quick_rule["level"] = self._level(int(quick_rule.get("confidence") or 0))
            quick_rule["classification"] = f"{quick_rule['level']}_CONFIDENCE"
        if (not best_match or best_score <= 0) and quick_rule:
            return quick_rule
        if not best_match or best_score <= 0:
            return {
                "matched": False,
                "device_name": provisional_label,
                "vendor": str(observation.get("vendor") or provisional_meta.get("vendor") or "Unknown"),
                "model": "",
                "category": provisional_label,
                "type": provisional_label,
                "classification_type": str(provisional_meta.get("device_type") or "Unknown"),
                "protocol": str(provisional_meta.get("protocol") or "BLE"),
                "confidence": provisional_confidence,
                "level": self._level(provisional_confidence),
                "classification": f"{self._level(provisional_confidence)}_CONFIDENCE",
                "pairing": "",
                "notes": "No exact fingerprint database match; provisional cluster classification applied.",
                "behavior_profile": {
                    "burst": int(observation.get("observation_count") or 0) <= 1,
                    "interval_stable": observation.get("advertising_interval_ms") is not None,
                    "connect_attempts": 0,
                },
                "risk_profile": "high" if self._normalize_bool(observation.get("connectable")) else "low",
                "match_reasons": ["provisional_cluster_classification"],
                "source": "provisional_cluster",
                "ui_tone": str(provisional_meta.get("ui_tone") or "neutral"),
                "icon": str(provisional_meta.get("icon") or "❓"),
            }

        classified_type = str(best_match.get("classification_type") or "Unknown")
        risk_profile = str(best_match.get("risk_profile") or ("medium" if classified_type == "IoT" else "low"))
        matched_result = {
            "matched": True,
            "device_name": str(best_match.get("name") or ""),
            "vendor": str(best_match.get("brand") or best_match.get("vendor") or observation.get("vendor") or "Unknown"),
            "model": str(best_match.get("model") or ""),
            "category": str(best_match.get("category") or "unknown"),
            "type": str(best_match.get("type") or "unknown"),
            "classification_type": classified_type,
            "protocol": str(best_match.get("protocol") or "BLE"),
            "confidence": max(provisional_confidence, max(15, min(100, best_score))),
            "level": level,
            "classification": f"{level}_CONFIDENCE",
            "pairing": str(best_match.get("pairing") or ""),
            "notes": str(best_match.get("notes") or ""),
            "behavior_profile": {
                "burst": int(observation.get("observation_count") or 0) <= 1,
                "interval_stable": observation.get("advertising_interval_ms") is not None,
                "connect_attempts": 0,
            },
            "risk_profile": risk_profile,
            "match_reasons": best_reasons,
            "source": str(best_match.get("source") or ""),
            "ui_tone": self._ui_tone(classified_type, risk_profile),
            "icon": self._icon(str(best_match.get("category") or ""), classified_type),
        }
        has_name_anchor = "name_match" in best_reasons or "name_alias_match" in best_reasons
        if quick_rule and not has_name_anchor and int(quick_rule.get("confidence") or 0) > int(matched_result.get("confidence") or 0):
            return quick_rule
        if provisional_confidence > int(matched_result.get("confidence") or 0):
            matched_result["confidence"] = provisional_confidence
            matched_result["level"] = self._level(provisional_confidence)
            matched_result["classification"] = f"{matched_result['level']}_CONFIDENCE"
        matched_result["provisional_classification"] = provisional_label
        matched_result["cluster_size"] = cluster_size
        return matched_result
