from __future__ import annotations

from typing import Any, Dict, List


class PassiveEventEngine:
    def summarize_channel_events(self, frames: List[Dict[str, Any]]) -> Dict[str, Any]:
        association_events = 0
        reassociation_events = 0
        authentication_events = 0
        probe_requests = 0
        eapol_frames = 0

        for frame in frames:
            subtype = str(frame.get("subtype_label") or "")
            if subtype == "association_request":
                association_events += 1
            elif subtype == "reassociation_request":
                reassociation_events += 1
            elif subtype == "authentication":
                authentication_events += 1
            elif subtype == "probe_request":
                probe_requests += 1
            if frame.get("eapol_type"):
                eapol_frames += 1

        probe_burst = probe_requests >= 6
        auth_activity = association_events + reassociation_events + authentication_events + eapol_frames
        return {
            "association_events": association_events,
            "reassociation_events": reassociation_events,
            "authentication_events": authentication_events,
            "probe_requests": probe_requests,
            "probe_burst": probe_burst,
            "eapol_frames": eapol_frames,
            "auth_activity": auth_activity,
        }

    def observation_opportunity(self, network: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        reasons: List[str] = []

        client_count = int(network.get("client_count") or 0)
        auth_events = int(network.get("auth_event_count") or 0)
        security = str(network.get("security") or "")
        pmf_enabled = str(network.get("pmf") or "").lower() in {"true", "1", "required", "capable"}
        packet_rate = float((network.get("flow_metrics") or {}).get("packet_rate_pps") or 0.0)
        mobility_events = int(network.get("mobility_event_count") or 0)
        probe_burst_count = int(network.get("probe_burst_count") or 0)

        if client_count >= 4:
            score += 25
            reasons.append(f"{client_count} active clients")
        elif client_count >= 2:
            score += 12
            reasons.append("multiple active clients")

        if auth_events >= 5:
            score += 25
            reasons.append(f"{auth_events} authentication-related events")
        elif auth_events >= 2:
            score += 12
            reasons.append("recurring authentication-related events")

        if "wpa2" in security.lower() and "wpa3" not in security.lower() and not pmf_enabled:
            score += 25
            reasons.append("WPA2 without PMF")
        elif "wpa3" in security.lower():
            score += 8
            reasons.append("WPA3 traffic observed")

        if packet_rate >= 6.0:
            score += 15
            reasons.append("high packet rate")
        elif packet_rate >= 2.5:
            score += 8
            reasons.append("steady packet rate")

        if mobility_events > 0:
            score += 5
            reasons.append("movement-related RSSI shifts")
        if probe_burst_count > 0:
            score += 5
            reasons.append("probe burst activity")

        level = "LOW"
        if score >= 65:
            level = "HIGH"
        elif score >= 35:
            level = "MEDIUM"

        return {
            "score": min(100, score),
            "level": level,
            "reasons": reasons[:6],
            "summary": " · ".join(reasons[:3]) if reasons else "limited passive authentication evidence",
        }
