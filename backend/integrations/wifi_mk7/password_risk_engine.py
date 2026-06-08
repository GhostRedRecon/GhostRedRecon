from __future__ import annotations

import re
from typing import Any, Dict, List

from backend.integrations.wifi_mk7.wifi_intelligence_profiles import (
    CHINESE_OEM_HINTS,
    DEFAULT_PASSWORD_HINTS,
    SPANISH_ISP_HINTS,
)


class WiFiPasswordRiskEngine:
    TOP_10K_GUESSES = 10_000
    CPU_HASHES_PER_SECOND = 75_000

    def assess_network(self, network: Dict[str, Any]) -> Dict[str, Any]:
        ssid = str(network.get("ssid") or "")
        vendor = str(network.get("vendor") or "")
        security = str(network.get("security") or "Unknown")
        akm = str(network.get("akm") or "")
        cipher = str(network.get("cipher") or "")
        pmf = str(network.get("pmf") or "")
        handshake_captured = bool(network.get("handshake_captured"))
        handshake_count = int(network.get("handshake_eapol_count") or network.get("eapol_count") or 0)
        wps_present = bool((network.get("security_posture") or {}).get("wps_present"))
        fingerprint = network.get("fingerprint") or {}

        handshake_intel = self._handshake_intelligence(security, akm, cipher, pmf, handshake_captured, handshake_count)
        password_model = self._password_probability_model(ssid, vendor, fingerprint, wps_present)
        feasibility = self._attack_feasibility_model(password_model, handshake_intel)
        verdict = self._final_verdict(handshake_intel, password_model, feasibility, wps_present)

        return {
            "enabled": True,
            "security_baseline": handshake_intel["baseline"],
            "handshake_intelligence": handshake_intel,
            "password_probability": password_model,
            "attack_feasibility": feasibility,
            "risk": verdict["risk"],
            "score": verdict["score"],
            "reason": verdict["reason"],
            "reasons": verdict["reasons"],
            "summary": verdict["summary"],
            "government_safe": True,
            "mode": "passive-policy-risk",
            "validation_pipeline": [
                "dumpcap",
                "tshark",
                "hcxtools-optional",
                "aircrack-ng-validation-only",
            ],
        }

    def _handshake_intelligence(
        self,
        security: str,
        akm: str,
        cipher: str,
        pmf: str,
        handshake_captured: bool,
        handshake_count: int,
    ) -> Dict[str, Any]:
        reasons: List[str] = []
        score = 35
        security_lower = security.lower()
        akm_lower = akm.lower()
        cipher_lower = cipher.lower()
        pmf_enabled = str(pmf or "").lower() in {"true", "1", "required", "capable"}
        wpa_version = "OPEN"

        if "sae" in akm_lower or "wpa3" in security_lower:
            wpa_version = "WPA3"
            score -= 18
            reasons.append("WPA3/SAE observed")
        elif "wpa2" in security_lower or akm_lower or cipher_lower:
            wpa_version = "WPA2"
            score += 18
            reasons.append("WPA2-era protection observed")
        elif "protected" in security_lower:
            wpa_version = "PROTECTED"
            score += 12
            reasons.append("privacy bit set without strong AKM details")
        else:
            wpa_version = "OPEN"
            score += 35
            reasons.append("open network")

        if "tkip" in cipher_lower:
            score += 20
            reasons.append("TKIP weak cipher")
        elif "ccmp" in cipher_lower or "aes" in cipher_lower:
            score += 2
            reasons.append("CCMP/AES observed")

        if not pmf_enabled and wpa_version in {"WPA2", "WPA3", "PROTECTED"}:
            score += 24
            reasons.append("PMF not observed")
        elif pmf_enabled:
            score -= 8
            reasons.append("PMF observed")

        if handshake_captured:
            score += 6
            reasons.append(f"passive handshake evidence retained ({handshake_count} EAPOL)")

        baseline = "STRONG"
        if score >= 78:
            baseline = "WEAK"
        elif score >= 58:
            baseline = "MODERATE"

        return {
            "wpa_version": wpa_version,
            "cipher": cipher or "--",
            "pmf_enabled": pmf_enabled,
            "handshake_captured": handshake_captured,
            "handshake_count": handshake_count,
            "baseline": baseline,
            "score": max(0, min(100, score)),
            "reasons": reasons[:6],
        }

    def _password_probability_model(
        self,
        ssid: str,
        vendor: str,
        fingerprint: Dict[str, Any],
        wps_present: bool,
    ) -> Dict[str, Any]:
        reasons: List[str] = []
        patterns: List[str] = []
        score = 22
        ssid_lower = ssid.lower()
        vendor_lower = vendor.lower()
        fingerprint_text = " ".join(
            str(fingerprint.get(key) or "")
            for key in ("device_type", "family", "role")
        ).lower()

        if wps_present:
            score += 18
            reasons.append("WPS metadata observed")
            patterns.append("wps-assisted setup pattern")

        if any(token in ssid_lower for token in SPANISH_ISP_HINTS):
            score += 24
            reasons.append("regional ISP naming pattern")
            patterns.append("Spanish ISP default pattern family")

        if any(token in vendor_lower or token in ssid_lower for token in CHINESE_OEM_HINTS):
            score += 14
            reasons.append("Chinese OEM / IoT default-key exposure pattern")
            patterns.append("OEM default credential family")

        if any(token in ssid_lower for token in DEFAULT_PASSWORD_HINTS):
            score += 26
            reasons.append("SSID contains a common default-password hint")
            patterns.append("top-10k style weak password theme")

        if re.search(r"(movistar|vodafone|orange|jazztel|digi)[_-]?[a-z0-9]{4,8}$", ssid_lower):
            score += 20
            reasons.append("SSID suffix resembles ISP-issued default naming")
            patterns.append("ISP suffix seed pattern")

        if re.search(r"[0-9]{8}$", ssid_lower):
            score += 15
            reasons.append("numeric suffix suggests predictable seed material")
            patterns.append("8-digit numeric seed")

        if re.search(r"[a-f0-9]{8,12}$", ssid_lower):
            score += 11
            reasons.append("hex-style suffix may map to vendor default derivation")
            patterns.append("hex-derived default key family")

        if "camera" in fingerprint_text or "iot" in fingerprint_text:
            score += 10
            reasons.append("IoT/camera profile often correlates with weaker provisioning defaults")
            patterns.append("IoT onboarding/default provisioning risk")

        if "<hidden>" in ssid_lower or not ssid_lower.strip():
            score -= 8
            reasons.append("no SSID naming pattern available")

        score = max(5, min(95, score))
        probability = "LOW"
        if score >= 70:
            probability = "HIGH"
        elif score >= 45:
            probability = "MEDIUM"

        candidate_space = self._candidate_space(score, patterns)
        return {
            "probability": probability,
            "score": score,
            "patterns": patterns[:5],
            "reasons": reasons[:6],
            "dictionary_success_probability": round(score / 100.0, 2),
            "candidate_space_estimate": candidate_space,
        }

    def _candidate_space(self, score: int, patterns: List[str]) -> int:
        if any("8-digit numeric" in pattern for pattern in patterns):
            return 10**8
        if any("ISP" in pattern or "OEM" in pattern for pattern in patterns):
            return 10**9
        if score >= 70:
            return 5 * 10**9
        if score >= 45:
            return 10**12
        return 10**16

    def _attack_feasibility_model(
        self,
        password_model: Dict[str, Any],
        handshake_intel: Dict[str, Any],
    ) -> Dict[str, Any]:
        candidate_space = int(password_model.get("candidate_space_estimate") or 10**12)
        top10k_seconds = self.TOP_10K_GUESSES / float(self.CPU_HASHES_PER_SECOND)
        brute_force_seconds = candidate_space / float(self.CPU_HASHES_PER_SECOND)
        handshake_ready = bool(handshake_intel.get("handshake_captured"))
        probability = float(password_model.get("dictionary_success_probability") or 0.0)

        if candidate_space <= 10**8:
            label = "minutes"
        elif candidate_space <= 10**9:
            label = "hours"
        elif candidate_space <= 10**12:
            label = "days"
        elif candidate_space <= 10**14:
            label = "months"
        else:
            label = "impractical"

        if not handshake_ready:
            label = "passive-only / handshake not retained"

        feasibility_score = min(
            100,
            int(
                round(
                    (password_model.get("score") or 0) * 0.65
                    + (12 if handshake_ready else 0)
                    + (10 if candidate_space <= 10**9 else 0)
                )
            ),
        )

        return {
            "handshake_ready": handshake_ready,
            "cpu_only_eta": label,
            "cpu_dictionary_seconds": round(top10k_seconds, 2),
            "cpu_bruteforce_seconds_estimate": round(brute_force_seconds, 2) if brute_force_seconds < 31_536_000 else None,
            "feasibility_score": feasibility_score,
            "dictionary_success_probability": probability,
        }

    def _final_verdict(
        self,
        handshake_intel: Dict[str, Any],
        password_model: Dict[str, Any],
        feasibility: Dict[str, Any],
        wps_present: bool,
    ) -> Dict[str, Any]:
        reasons: List[str] = []
        score = 0

        score += int(handshake_intel.get("score") or 0) * 0.5
        score += int(password_model.get("score") or 0) * 0.35
        score += int(feasibility.get("feasibility_score") or 0) * 0.15

        if handshake_intel.get("baseline") == "WEAK":
            reasons.append("weak handshake/security baseline")
        if not handshake_intel.get("pmf_enabled") and handshake_intel.get("wpa_version") in {"WPA2", "PROTECTED"}:
            reasons.append("no PMF")
        if password_model.get("probability") == "HIGH":
            reasons.append("likely default or dictionary-shaped password")
        if wps_present:
            reasons.append("WPS metadata present")
        if feasibility.get("cpu_only_eta") in {"minutes", "hours", "days"}:
            reasons.append(f"CPU-only feasibility estimated in {feasibility.get('cpu_only_eta')}")
        if handshake_intel.get("wpa_version") == "WPA3":
            reasons.append("WPA3/SAE raises the baseline")
        if handshake_intel.get("wpa_version") == "WPA2" and not handshake_intel.get("pmf_enabled"):
            score += 10
        if handshake_intel.get("wpa_version") == "OPEN":
            score += 18
        if password_model.get("probability") == "MEDIUM":
            score += 8

        final_score = max(0, min(100, int(round(score))))
        risk = "LOW"
        if final_score >= 80:
            risk = "CRITICAL"
        elif final_score >= 60:
            risk = "HIGH"
        elif final_score >= 35:
            risk = "MEDIUM"

        reason = reasons[0] if reasons else "baseline passive WiFi password risk"
        summary = " · ".join(reasons[:3]) if reasons else "baseline passive WiFi password risk"
        return {
            "risk": risk,
            "score": final_score,
            "reason": reason,
            "reasons": reasons[:6],
            "summary": summary,
        }
