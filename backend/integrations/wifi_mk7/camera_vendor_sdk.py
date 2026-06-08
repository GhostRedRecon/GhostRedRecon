from __future__ import annotations

from typing import Any, Dict, List


class CameraVendorPluginRegistry:
    def __init__(self) -> None:
        self._plugins = [
            XiaomiVendorPlugin(),
            TapoVendorPlugin(),
            WyzeVendorPlugin(),
            ReolinkVendorPlugin(),
            YiVendorPlugin(),
        ]

    def match(self, lead: Dict[str, Any], analysis: Dict[str, Any] | None = None) -> Dict[str, Any]:
        matches: List[Dict[str, Any]] = []
        for plugin in self._plugins:
            profile = plugin.describe(lead, analysis=analysis)
            if profile.get("matched"):
                matches.append(profile)
        primary = matches[0] if matches else {
            "matched": False,
            "plugin_id": "",
            "label": "Generic Camera",
            "vendor_family": "",
            "local_capture_paths": [],
            "bridge_targets": [],
            "owner_assisted_workflow": [],
            "recorder_replay": {},
            "notes": [],
        }
        return {
            "primary": primary,
            "matches": matches,
        }


class _BaseVendorPlugin:
    plugin_id = ""
    label = ""
    vendor_tokens: tuple[str, ...] = ()
    family_tokens: tuple[str, ...] = ()

    def describe(self, lead: Dict[str, Any], analysis: Dict[str, Any] | None = None) -> Dict[str, Any]:
        lead_blob = self._lead_blob(lead, analysis=analysis)
        matched = any(token in lead_blob for token in [*self.vendor_tokens, *self.family_tokens])
        if not matched:
            return {"matched": False, "plugin_id": self.plugin_id, "label": self.label}
        return {
            "matched": True,
            "plugin_id": self.plugin_id,
            "label": self.label,
            "vendor_family": self.plugin_id,
            "local_capture_paths": self.local_capture_paths(lead),
            "bridge_targets": self.bridge_targets(lead),
            "owner_assisted_workflow": self.owner_assisted_workflow(lead),
            "recorder_replay": self.recorder_replay(lead),
            "notes": self.notes(lead),
        }

    def local_capture_paths(self, lead: Dict[str, Any]) -> List[str]:
        return []

    def bridge_targets(self, lead: Dict[str, Any]) -> List[str]:
        return []

    def owner_assisted_workflow(self, lead: Dict[str, Any]) -> List[str]:
        return []

    def recorder_replay(self, lead: Dict[str, Any]) -> Dict[str, Any]:
        return {"supported": False, "detail": "No recorder replay guidance retained."}

    def notes(self, lead: Dict[str, Any]) -> List[str]:
        return []

    @staticmethod
    def _lead_blob(lead: Dict[str, Any], analysis: Dict[str, Any] | None = None) -> str:
        return " ".join(
            [
                str(lead.get("vendor") or ""),
                str(lead.get("historical_identity_hint") or ""),
                " ".join(str(item) for item in (lead.get("related_identity_hints") or [])),
                str(((lead.get("camera_detection") or {}).get("family_match") or "")),
                str(((lead.get("stable_fingerprint") or {}).get("associated_network_ssid") or "")),
                " ".join(str(item) for item in (((lead.get("service_exposure") or {}).get("cloud_endpoints")) or [])),
                " ".join(str(item) for item in ((((analysis or {}).get("analysis") or {}).get("cloud_endpoints")) or [])),
            ]
        ).lower()


class XiaomiVendorPlugin(_BaseVendorPlugin):
    plugin_id = "xiaomi"
    label = "Xiaomi / Mi Home"
    vendor_tokens = ("xiaomi", "mijia", "imilab", "chuangmi", "zhen shi", "miio", "miiot")
    family_tokens = ("xiaomi_mi_imilab_mijia", "chuangmi")

    def local_capture_paths(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "HTTP snapshot if stock firmware exposes it",
            "miIO / MIoT local API when UDP 54321 is reachable",
            "RTSP only when model or firmware enables it",
        ]

    def bridge_targets(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "HLS playlist or relay URL recovered from owner-consented app session",
            "App-assisted WebRTC or proprietary relay bridge when local RTSP is absent",
        ]

    def owner_assisted_workflow(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Open live view in Xiaomi Home / Mi Home during Hard Audit",
            "Record phone-side endpoint, playlist, and session timing correlation",
            "Retain app-assisted screenshot or screen recording as owner-assisted visual proof",
        ]

    def notes(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Stock Xiaomi cameras are commonly cloud-first and may expose no local RTSP path.",
            "Visual proof often depends on owner-assisted app-side capture when local media is unavailable.",
        ]


class TapoVendorPlugin(_BaseVendorPlugin):
    plugin_id = "tapo"
    label = "TP-Link Tapo"
    vendor_tokens = ("tapo", "tp-link", "tplink")
    family_tokens = ("tapo",)

    def local_capture_paths(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "ONVIF snapshot and media service",
            "RTSP main and sub streams",
            "HTTP snapshot on model-specific endpoints",
        ]

    def bridge_targets(self, lead: Dict[str, Any]) -> List[str]:
        return ["Owner-assisted app relay capture when RTSP is disabled"]

    def owner_assisted_workflow(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Validate RTSP / ONVIF first",
            "If disabled, open Tapo app live view and retain correlated traffic with client-side visual proof",
        ]

    def recorder_replay(self, lead: Dict[str, Any]) -> Dict[str, Any]:
        return {"supported": True, "detail": "Check ONVIF recorder or SD-card playback path if local stream is exposed."}


class WyzeVendorPlugin(_BaseVendorPlugin):
    plugin_id = "wyze"
    label = "Wyze"
    vendor_tokens = ("wyze",)
    family_tokens = ("wyze",)

    def local_capture_paths(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Local bridge or RTSP only when enabled by firmware or compatible bridge tooling",
            "HTTP snapshot is uncommon on stock cloud-first models",
        ]

    def bridge_targets(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Vendor-local bridge into RTSP or HLS when supported",
            "Owner-assisted app session relay capture",
        ]

    def owner_assisted_workflow(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Open Wyze live view and capture correlated packet deltas",
            "Retain owner-assisted screen evidence when no local stream is exposed",
        ]

    def notes(self, lead: Dict[str, Any]) -> List[str]:
        return ["Wyze-family devices are frequently cloud-first and require a bridge or owner-assisted evidence path."]


class ReolinkVendorPlugin(_BaseVendorPlugin):
    plugin_id = "reolink"
    label = "Reolink"
    vendor_tokens = ("reolink",)
    family_tokens = ("reolink",)

    def local_capture_paths(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "RTSP main and sub streams",
            "ONVIF snapshot and media service",
            "HTTP snapshot or recorder replay when attached to an NVR",
        ]

    def bridge_targets(self, lead: Dict[str, Any]) -> List[str]:
        return ["Recorder replay through NVR or proprietary bridge when local RTSP path is non-standard"]

    def recorder_replay(self, lead: Dict[str, Any]) -> Dict[str, Any]:
        return {"supported": True, "detail": "Reolink-family recorders often provide a replay surface even when camera media is proxied through the NVR."}


class YiVendorPlugin(_BaseVendorPlugin):
    plugin_id = "yi"
    label = "Yi / Kami"
    vendor_tokens = ("yi", "kami")
    family_tokens = ("yi",)

    def local_capture_paths(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "HTTP snapshot when firmware exposes it",
            "RTSP or ONVIF only on supported models or modified firmware",
        ]

    def bridge_targets(self, lead: Dict[str, Any]) -> List[str]:
        return ["Owner-assisted relay capture or firmware-enabled RTSP path"]

    def owner_assisted_workflow(self, lead: Dict[str, Any]) -> List[str]:
        return [
            "Check stock local HTTP or snapshot surface first",
            "If unavailable, retain owner-assisted client-side visual proof during live view",
        ]

    def notes(self, lead: Dict[str, Any]) -> List[str]:
        return ["Yi-family visual recovery varies heavily by model and firmware generation."]
