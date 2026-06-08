from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


class LoRaLabProfileMatcher:
    VERSION = "1.0.0"
    DEFAULT_PATH = os.path.join(BASE_DIR, "backend", "config", "lora_lab_device_profiles.yaml")

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("GHOSTRECON_LORA_PROFILE_DB") or self.DEFAULT_PATH

    def load_profiles(self) -> List[Dict[str, Any]]:
        if not self.db_path or not os.path.exists(self.db_path):
            return []
        try:
            with open(self.db_path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception:
            return []

        if isinstance(data, list):
            return [entry for entry in data if isinstance(entry, dict)]
        if isinstance(data, dict):
            raw = data.get("profiles") or []
            return [entry for entry in raw if isinstance(entry, dict)]
        return []

    def match_device(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        candidates = self.rank_device(device, limit=1)
        if not candidates:
            return None
        best = candidates[0]
        if self._safe_float(best.get("confidence")) is None or float(best["confidence"]) < 0.62:
            return None
        return best

    def rank_device(self, device: Dict[str, Any], limit: int = 3) -> List[Dict[str, Any]]:
        profiles = self.load_profiles()
        if not profiles or not isinstance(device, dict):
            return []

        ranked = []
        for profile in profiles:
            score = self._score(profile, device)
            ranked.append(
                {
                    "vendor": profile.get("vendor"),
                    "product": profile.get("product"),
                    "device_type": profile.get("device_type"),
                    "profile_name": profile.get("profile_name") or profile.get("product"),
                    "confidence": round(score, 4),
                    "tags": list(profile.get("tags") or []),
                    "source_url": profile.get("source_url"),
                    "identity_family": profile.get("identity_family"),
                    "role": profile.get("role"),
                    "bandplan": profile.get("bandplan"),
                }
            )

        ranked.sort(key=lambda item: float(item.get("confidence") or 0.0), reverse=True)
        return [item for item in ranked[: max(1, int(limit))] if float(item.get("confidence") or 0.0) > 0.15]

    def _score(self, profile: Dict[str, Any], device: Dict[str, Any]) -> float:
        score = 0.0

        bandplan = str(device.get("lora_bandplan") or "").strip().lower()
        region = str(device.get("lora_network_region") or "").strip().lower()
        cadence = str(device.get("lora_cadence_class") or "").strip().lower()
        family = str(device.get("lora_identity_family") or "").strip().lower()
        role = str(device.get("lora_role") or device.get("device_role_hint") or "").strip().lower()
        device_type_hint = str(device.get("lora_device_type_hint") or device.get("device_type") or "").strip().lower()

        profile_bandplan = str(profile.get("bandplan") or "").strip().lower()
        profile_region = str(profile.get("region") or "").strip().lower()
        profile_cadence = str(profile.get("cadence_class") or "").strip().lower()
        profile_family = str(profile.get("identity_family") or "").strip().lower()
        profile_role = str(profile.get("role") or "").strip().lower()
        profile_type = str(profile.get("device_type") or "").strip().lower()

        if bandplan and profile_bandplan and bandplan == profile_bandplan:
            score += 0.24
        elif region and profile_region and region == profile_region:
            score += 0.18

        if cadence and profile_cadence and cadence == profile_cadence:
            score += 0.14
        if family and profile_family and family == profile_family:
            score += 0.18
        if role and profile_role and role == profile_role:
            score += 0.10
        if profile_type and device_type_hint and profile_type == device_type_hint:
            score += 0.08

        freq_score = self._freq_score(profile, device)
        score += freq_score

        span = self._safe_float(device.get("lora_dwell_span_mhz"))
        prof_span = self._safe_float(profile.get("dwell_span_mhz"))
        if span is not None and prof_span is not None:
            if abs(span - prof_span) <= 0.4:
                score += 0.08
            elif abs(span - prof_span) <= 1.2:
                score += 0.03

        count = self._safe_float(device.get("lora_frequency_count"))
        prof_count = self._safe_float(profile.get("frequency_count"))
        if count is not None and prof_count is not None:
            if abs(count - prof_count) <= 1:
                score += 0.06
            elif abs(count - prof_count) <= 3:
                score += 0.03

        bandwidth = self._safe_float(device.get("bandwidth_estimate_mhz"))
        prof_bandwidth = self._safe_float(profile.get("bandwidth_mhz"))
        if bandwidth is not None and prof_bandwidth is not None:
            if abs(bandwidth - prof_bandwidth) <= 0.08:
                score += 0.05
            elif abs(bandwidth - prof_bandwidth) <= 0.20:
                score += 0.02

        return min(score, 1.0)

    def _freq_score(self, profile: Dict[str, Any], device: Dict[str, Any]) -> float:
        profile_center = self._safe_float(profile.get("center_freq_mhz"))
        device_freqs = [self._safe_float(v) for v in (device.get("frequencies") or [])]
        device_freqs = [v for v in device_freqs if v is not None]
        if not device_freqs:
            return 0.0
        device_center = sum(device_freqs) / len(device_freqs)
        if profile_center is None:
            return 0.0
        delta = abs(device_center - profile_center)
        if delta <= 0.20:
            return 0.20
        if delta <= 0.60:
            return 0.14
        if delta <= 1.20:
            return 0.08
        return 0.0

    @staticmethod
    def _safe_float(value: Any) -> Optional[float]:
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None
