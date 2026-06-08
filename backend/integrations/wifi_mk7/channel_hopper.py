from __future__ import annotations

from typing import Any, Dict, List


class ChannelHopper:
    CHANNELS_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    # Prefer non-DFS passive-safe channels for the default production sweep.
    CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
    CHANNELS_5_DFS = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]
    HANDSHAKE_PRIORITY = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]

    @staticmethod
    def _band_for_channel(channel: int) -> str:
        return "2.4 GHz" if int(channel) <= 14 else "5 GHz"

    def build_plan(
        self,
        bands: List[str] | None = None,
        dwell_ms: int = 250,
        locked_channels: List[int] | None = None,
        hot_channels: List[int] | None = None,
        channel_activity: Dict[int, Dict[str, Any]] | None = None,
        scan_mode: str = "broad",
    ) -> List[Dict[str, Any]]:
        requested = {str(item or "").strip().lower() for item in (bands or ["2.4ghz", "5ghz"])}
        plan: List[Dict[str, Any]] = []
        allowed_channels: List[int] = []
        include_dfs = scan_mode in {"residential_dfs", "adaptive_residential_dfs"}
        adaptive_modes = {"adaptive", "adaptive_residential_dfs", "adaptive_handshake_hunt"}
        handshake_modes = {"handshake_hunt", "adaptive_handshake_hunt"}
        handshake_mode = scan_mode in handshake_modes

        if requested & {"2.4", "2.4ghz", "2.4 ghz", "all"}:
            allowed_channels.extend(self.CHANNELS_24)

        if requested & {"5", "5ghz", "5 ghz", "all"}:
            allowed_channels.extend(self.CHANNELS_5)
            if include_dfs:
                allowed_channels.extend(self.CHANNELS_5_DFS)

        if locked_channels:
            normalized = [int(channel) for channel in locked_channels if int(channel) in allowed_channels]
            allowed_channels = normalized or allowed_channels

        hot = [int(channel) for channel in (hot_channels or []) if int(channel) in allowed_channels]
        if handshake_mode:
            activity_map = channel_activity or {}
            priority_order = {channel: index for index, channel in enumerate(self.HANDSHAKE_PRIORITY)}

            def handshake_score(channel: int) -> tuple[float, float, float, float]:
                activity = activity_map.get(int(channel), {})
                eapol_frames = float(activity.get("eapol_frames") or 0)
                auth_activity = float(activity.get("auth_activity") or 0)
                authentication_events = float(activity.get("authentication_events") or 0)
                association_events = float(activity.get("association_events") or 0) + float(activity.get("reassociation_events") or 0)
                probe_requests = float(activity.get("probe_requests") or 0)
                packet_volume = float(activity.get("frames") or 0)
                handshake_priority = 120.0 if int(channel) in hot[: min(8, len(hot))] else 0.0
                return (
                    eapol_frames * 28.0
                    + auth_activity * 12.0
                    + authentication_events * 10.0
                    + association_events * 7.0
                    + probe_requests * 3.0
                    + min(packet_volume, 180.0) * 0.15
                    + handshake_priority,
                    eapol_frames,
                    auth_activity,
                    packet_volume,
                )

            ordered_channels = sorted(
                allowed_channels,
                key=lambda channel: (
                    handshake_score(channel)[0],
                    -priority_order.get(int(channel), 999),
                ),
                reverse=True,
            )
            if not any(handshake_score(channel)[0] > 0 for channel in ordered_channels):
                ordered_channels = sorted(
                    allowed_channels,
                    key=lambda channel: priority_order.get(int(channel), 999),
                )
            revisit_channels = [
                channel for channel in ordered_channels
                if handshake_score(channel)[0] >= 12.0
            ][: min(3, len(ordered_channels))]
            if revisit_channels and not locked_channels:
                ordered_channels = [*ordered_channels, *revisit_channels]
        elif scan_mode in adaptive_modes and hot:
            ordered_channels = hot + [channel for channel in allowed_channels if channel not in hot]
        else:
            ordered_channels = allowed_channels

        for index, channel in enumerate(ordered_channels):
            entry_dwell = int(dwell_ms)
            activity = (channel_activity or {}).get(int(channel), {})
            if handshake_mode:
                eapol_frames = int(activity.get("eapol_frames") or 0)
                auth_activity = int(activity.get("auth_activity") or 0)
                authentication_events = int(activity.get("authentication_events") or 0)
                association_events = int(activity.get("association_events") or 0) + int(activity.get("reassociation_events") or 0)
                probe_requests = int(activity.get("probe_requests") or 0)
                handshake_visible = eapol_frames > 0 or auth_activity > 0 or authentication_events > 0 or association_events > 0
                entry_dwell = int(max(dwell_ms, 900))
                if eapol_frames >= 4:
                    entry_dwell = int(min(4500, max(entry_dwell, dwell_ms * 6)))
                elif eapol_frames >= 1 or auth_activity >= 4:
                    entry_dwell = int(min(3600, max(entry_dwell, dwell_ms * 5)))
                elif authentication_events >= 1 or association_events >= 2:
                    entry_dwell = int(min(2800, max(entry_dwell, dwell_ms * 4)))
                elif probe_requests >= 3 or int(channel) in hot[: min(6, len(hot))]:
                    entry_dwell = int(min(2200, max(entry_dwell, dwell_ms * 3)))
                elif not handshake_visible:
                    entry_dwell = int(min(1400, max(entry_dwell, dwell_ms * 2)))
            elif scan_mode in adaptive_modes and hot and channel in hot[: min(6, len(hot))]:
                entry_dwell = int(min(3000, max(dwell_ms, dwell_ms * 2)))
            auth_activity = int(activity.get("auth_activity") or 0)
            packet_volume = int(activity.get("frames") or 0)
            eapol_frames = int(activity.get("eapol_frames") or 0)
            if not handshake_mode and auth_activity >= 8:
                entry_dwell = int(min(3000, max(entry_dwell, dwell_ms * 3)))
            elif not handshake_mode and (auth_activity >= 3 or packet_volume >= 80):
                entry_dwell = int(min(3000, max(entry_dwell, dwell_ms * 2)))
            elif not handshake_mode and packet_volume <= 8:
                entry_dwell = int(max(100, min(entry_dwell, dwell_ms)))
            plan.append(
                {
                    "channel": channel,
                    "band": self._band_for_channel(channel),
                    "dwell_ms": entry_dwell,
                    "priority": (
                        "handshake_hot"
                        if handshake_mode and (eapol_frames > 0 or auth_activity > 0 or channel in hot)
                        else "hot"
                        if channel in hot
                        else ("locked" if locked_channels else "normal")
                    ),
                    "auth_activity": auth_activity,
                    "eapol_frames": eapol_frames,
                    "observed_frames": packet_volume,
                    "sequence": index + 1,
                }
            )

        return plan
