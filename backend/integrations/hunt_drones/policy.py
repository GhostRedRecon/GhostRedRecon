from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


DISABLED_OPERATOR_FEATURES = (
    ("jamming", "Signal blocking and jamming controls are disabled on the backend."),
    ("injection", "Packet injection controls are disabled on the backend."),
    ("transmit_sdr", "SDR transmit controls are disabled on the backend."),
    ("deauth", "Deauthentication controls are disabled on the backend."),
    ("spoofing", "Spoofing controls are disabled on the backend."),
    ("rerouting", "Rerouting controls are disabled on the backend."),
    ("takeover", "Takeover controls are disabled on the backend."),
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason}


class ReceiveOnlyGuard:
    def __init__(self) -> None:
        self._locked = True

    def status(self) -> Dict[str, Any]:
        return {
            "locked": True,
            "mode": "receive_only",
            "summary": "Receive-only policy enforced across UI, API, and backend workflows.",
            "disabled_features": [name for name, _ in DISABLED_OPERATOR_FEATURES],
        }

    def enforce(self, capability: str) -> PolicyDecision:
        lowered = str(capability or "").strip().lower()
        for name, message in DISABLED_OPERATOR_FEATURES:
            if lowered == name:
                return PolicyDecision(False, "The feature has been disabled on the backend.")
        return PolicyDecision(True, "Passive capability allowed.")


class ToolCapabilityPolicy:
    def __init__(self, guard: ReceiveOnlyGuard) -> None:
        self.guard = guard

    def as_settings(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for name, message in DISABLED_OPERATOR_FEATURES:
            rows.append(
                {
                    "name": name,
                    "operator_state": "Disabled",
                    "backend_state": "Disabled",
                    "reason": message,
                }
            )
        return rows


class ResearchFeatureGate:
    def __init__(self) -> None:
        self._features = [
            "lab_jamming_research",
            "lab_injection_research",
            "lab_transmit_sdr_research",
            "lab_takeover_research",
            "lab_gnss_research",
        ]

    def as_settings(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": feature,
                "state": "Disabled",
                "visibility": "Hidden in field mode",
                "build_availability": "Excluded from standard builds",
            }
            for feature in self._features
        ]


class SettingsSafetyEnforcer:
    def __init__(self, guard: ReceiveOnlyGuard, tool_policy: ToolCapabilityPolicy, research_gate: ResearchFeatureGate) -> None:
        self.guard = guard
        self.tool_policy = tool_policy
        self.research_gate = research_gate

    def build_settings(self, scan_profiles: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "policy": {
                "receive_only": self.guard.status(),
                "operator_blocks": self.tool_policy.as_settings(),
                "research_blocks": self.research_gate.as_settings(),
            },
            "scan_profiles": scan_profiles,
            "safety_sections": [
                {"name": "jamming", "state": "Disabled"},
                {"name": "injection", "state": "Disabled"},
                {"name": "transmit_sdr", "state": "Disabled"},
                {"name": "deauth", "state": "Disabled"},
                {"name": "spoofing", "state": "Disabled"},
                {"name": "rerouting", "state": "Disabled"},
                {"name": "takeover", "state": "Disabled"},
            ],
        }
