from __future__ import annotations

from typing import Any, Dict, List, Tuple


GROUP_SPECS: Dict[str, Dict[str, Any]] = {
    "AP": {"label": "Access Point", "color": "green", "sort_order": 1},
    "CAMERA": {"label": "Camera / Video", "color": "purple", "sort_order": 2},
    "IOT": {"label": "IoT Device", "color": "yellow", "sort_order": 3},
    "INFRASTRUCTURE": {"label": "Infrastructure", "color": "red", "sort_order": 4},
    "CLIENT": {"label": "Client Device", "color": "blue", "sort_order": 5},
    "UNKNOWN": {"label": "Unknown", "color": "gray", "sort_order": 6},
}

CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


class DeviceClassifier:
    """Evidence-first passive Wi-Fi device grouping."""

    def classify_device(
        self,
        item: Dict[str, Any],
        *,
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
        behavior: Dict[str, Any],
        role_duel: Dict[str, Any],
        stream_state: Dict[str, Any],
        camera_confirmation: Dict[str, Any],
    ) -> Dict[str, Any]:
        if self._is_access_point(item, fingerprint):
            signals = self._dedupe(
                [
                    "beacon_frames" if int(item.get("beacon_count") or 0) > 0 else "",
                    "ssid_present" if str(item.get("ssid") or "").strip() else "",
                    "channel_ownership" if str(item.get("channel") or "").strip() else "",
                    "ap_role",
                ]
            )
            confidence = "HIGH" if len(signals) >= 3 else "MEDIUM"
            return self._build_result(
                group="AP",
                confidence=confidence,
                method="passive_packet_truth",
                signals=signals,
                explanation="Beacon ownership and SSID/channel evidence show this device is acting as an access point.",
                item=item,
                fingerprint=fingerprint,
            )

        camera_result = self._camera_decision(item, fingerprint, services, camera, role_duel, stream_state, camera_confirmation)
        if camera_result:
            return camera_result

        infra_result = self._infrastructure_decision(item, fingerprint, services, role_duel)
        if infra_result:
            return infra_result

        iot_result = self._iot_decision(item, fingerprint, services, behavior, role_duel, camera, stream_state)
        if iot_result:
            return iot_result

        client_result = self._client_decision(item, fingerprint, services, behavior)
        if client_result:
            return client_result

        return self._build_result(
            group="UNKNOWN",
            confidence="LOW",
            method="passive_packet_truth",
            signals=[],
            explanation="Insufficient packet-backed evidence exists to classify this device beyond an observed Wi-Fi participant.",
            item=item,
            fingerprint=fingerprint,
        )

    @staticmethod
    def _is_access_point(item: Dict[str, Any], fingerprint: Dict[str, Any]) -> bool:
        if str(fingerprint.get("role") or "").upper() == "AP":
            return True
        if int(item.get("beacon_count") or 0) > 0 and str(item.get("bssid") or "").strip():
            return True
        return False

    def _camera_decision(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
        role_duel: Dict[str, Any],
        stream_state: Dict[str, Any],
        camera_confirmation: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        protocols = set(services.get("protocols") or [])
        confirmation_level = str(camera_confirmation.get("level") or "").lower()
        strong_protocol = bool(protocols.intersection({"RTSP", "ONVIF"}))
        media_state = str(stream_state.get("state") or "")
        role_margin = float(role_duel.get("margin") or 0.0)
        role_winner = str(role_duel.get("winner_role") or "")
        family_match = str(camera.get("family_match") or "")
        quorum_count = int(((camera.get("camera_evidence_quorum") or {}).get("count") or 0))
        confidence_score = float(camera.get("score") or 0.0)
        signals = self._dedupe(
            [
                "vendor_camera_family" if family_match else "",
                "camera_protocol" if strong_protocol else "",
                "cloud_media_path" if str(stream_state.get("transport") or "") in {"cloud", "hybrid"} and list(services.get("cloud_endpoints") or []) else "",
                "behavioral_stream_state" if media_state in {"media_path_confirmed", "artifact_recovered"} else "",
                "camera_confirmation" if confirmation_level in {"confirmed", "artifact_confirmed"} else "",
                "wps_camera_type" if bool(item.get("wps_primary_device_camera")) else "",
                "role_duel_camera" if role_winner == "camera" else "",
            ]
        )
        strong_evidence = bool(
            strong_protocol
            or confirmation_level in {"confirmed", "artifact_confirmed"}
            or media_state in {"media_path_confirmed", "artifact_recovered"}
        )
        moderate_evidence = bool(
            camera.get("detected")
            and role_winner == "camera"
            and role_margin >= 8.0
            and quorum_count >= 2
            and (family_match or bool(item.get("wps_primary_device_camera")))
        )
        if not strong_evidence and not moderate_evidence:
            return None
        if strong_evidence and (strong_protocol or confirmation_level in {"confirmed", "artifact_confirmed"}) and len(signals) >= 3:
            confidence = "HIGH"
        elif len(signals) >= 2 and (moderate_evidence or confidence_score >= 60.0):
            confidence = "MEDIUM"
        else:
            return None
        explanation = (
            "Packet truth retains camera-specific identity plus a media-path or scenario-confirmed video signal."
            if confidence == "HIGH"
            else "Camera classification is supported by multiple packet-backed identity and behavior signals, but local media proof is still limited."
        )
        return self._build_result(
            group="CAMERA",
            confidence=confidence,
            method="passive_packet_truth",
            signals=signals,
            explanation=explanation,
            item=item,
            fingerprint=fingerprint,
        )

    def _infrastructure_decision(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        role_duel: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        vendor_family = str(fingerprint.get("vendor_family") or "")
        product_category = str(fingerprint.get("product_category") or "")
        role_winner = str(role_duel.get("winner_role") or "")
        role_margin = float(role_duel.get("margin") or 0.0)
        client_count = int(item.get("client_count") or 0)
        associated_bssids = len(item.get("associated_bssids") or [])
        protocols = set(services.get("protocols") or [])
        infrastructure_vendor = vendor_family in {"ubiquiti_unifi", "tplink_tapo_kasa"} or any(
            token in str(item.get("vendor") or "").lower()
            for token in ("ubiquiti", "unifi", "cisco", "mikrotik", "juniper", "aruba")
        )
        infrastructure_category = product_category in {"router_ap", "mesh_extender", "iot_hub"}
        topology_signal = client_count >= 2 or associated_bssids >= 2
        service_signal = "SSDP/UPnP" in protocols or "MQTT" in protocols
        if role_winner not in {"router", "hub", "nvr"} and not (infrastructure_vendor and topology_signal):
            return None
        signals = self._dedupe(
            [
                f"role_duel_{role_winner}" if role_winner else "",
                "multi_association_topology" if topology_signal else "",
                "infrastructure_vendor" if infrastructure_vendor else "",
                "service_advertisement" if service_signal else "",
                f"product_category_{product_category}" if infrastructure_category else "",
            ]
        )
        confidence = "HIGH" if role_margin >= 10.0 and len(signals) >= 3 else "MEDIUM"
        explanation = "Topology and infrastructure-oriented service behavior show this device is acting as network backbone equipment."
        return self._build_result(
            group="INFRASTRUCTURE",
            confidence=confidence,
            method="passive_packet_truth",
            signals=signals,
            explanation=explanation,
            item=item,
            fingerprint=fingerprint,
        )

    def _iot_decision(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        behavior: Dict[str, Any],
        role_duel: Dict[str, Any],
        camera: Dict[str, Any],
        stream_state: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        product_category = str(fingerprint.get("product_category") or "")
        vendor_family = str(fingerprint.get("vendor_family") or "")
        role_winner = str(role_duel.get("winner_role") or "")
        traffic_pattern = str(item.get("traffic_pattern") or "")
        cloud_endpoints = list(services.get("cloud_endpoints") or [])
        protocols = set(services.get("protocols") or [])
        known_iot_category = product_category in {
            "doorbell_camera",
            "baby_monitor",
            "pet_camera",
            "vacuum",
            "printer",
            "iot_hub",
            "tv_media",
            "mesh_extender",
        }
        embedded_vendor = bool(vendor_family) and vendor_family not in {"apple", "samsung_smartthings"}
        passive_iot_behavior = traffic_pattern in {"periodic", "mixed", "steady-stream"} or bool((item.get("flow_metrics") or {}).get("long_lived_flow"))
        cloud_signal = bool(cloud_endpoints or protocols.intersection({"TLS", "QUIC", "MQTT"}))
        weak_camera = bool(str(camera.get("family_match") or "") and not camera.get("detected"))
        if not any((known_iot_category, embedded_vendor, passive_iot_behavior, cloud_signal, role_winner == "generic_iot", weak_camera)):
            return None
        signals = self._dedupe(
            [
                f"product_category_{product_category}" if product_category else "",
                f"vendor_family_{vendor_family}" if vendor_family else "",
                "periodic_or_embedded_traffic" if passive_iot_behavior else "",
                "cloud_connected" if cloud_signal else "",
                "generic_iot_role_duel" if role_winner == "generic_iot" else "",
                "camera_not_proven" if weak_camera else "",
            ]
        )
        if weak_camera and not bool(protocols.intersection({"RTSP", "ONVIF"})):
            explanation = "The device shows an IoT or cloud-managed profile, but packet truth does not justify upgrading it to a camera classification yet."
        else:
            explanation = "Passive identity, traffic, and cloud/service signals fit an embedded IoT device profile."
        confidence = "HIGH" if len(signals) >= 4 and known_iot_category else ("MEDIUM" if len(signals) >= 2 else "LOW")
        return self._build_result(
            group="IOT",
            confidence=confidence,
            method="passive_packet_truth",
            signals=signals,
            explanation=explanation,
            item=item,
            fingerprint=fingerprint,
        )

    def _client_decision(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        behavior: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        product_category = str(fingerprint.get("product_category") or "")
        vendor_family = str(fingerprint.get("vendor_family") or "")
        mobility_class = str(item.get("mobility_class") or "")
        probe_count = int(item.get("probe_request_count") or 0)
        associated_bssid = str(item.get("associated_bssid") or "").strip()
        traffic_pattern = str(item.get("traffic_pattern") or "")
        phone_like = product_category == "phone" or vendor_family in {"apple", "samsung_smartthings"} or mobility_class in {"mobile", "portable"}
        general_client = bool(associated_bssid or probe_count > 0 or traffic_pattern)
        if not phone_like and not general_client:
            return None
        signals = self._dedupe(
            [
                f"product_category_{product_category}" if product_category else "",
                f"vendor_family_{vendor_family}" if vendor_family else "",
                "associated_client" if associated_bssid else "",
                "probe_activity" if probe_count > 0 else "",
                "mobility_pattern" if mobility_class and mobility_class != "static" else "",
                "general_traffic" if behavior.get("summary") or traffic_pattern else "",
            ]
        )
        confidence = "MEDIUM" if len(signals) >= 2 else "LOW"
        explanation = "Association and general traffic patterns fit a general client device, with no stronger role identity proven by packet truth."
        return self._build_result(
            group="CLIENT",
            confidence=confidence,
            method="passive_packet_truth",
            signals=signals,
            explanation=explanation,
            item=item,
            fingerprint=fingerprint,
        )

    def _build_result(
        self,
        *,
        group: str,
        confidence: str,
        method: str,
        signals: List[str],
        explanation: str,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
    ) -> Dict[str, Any]:
        spec = GROUP_SPECS.get(group, GROUP_SPECS["UNKNOWN"])
        product_category = str(fingerprint.get("product_category") or "")
        vendor_family = str(fingerprint.get("vendor_family") or "")
        return {
            "device_group": group,
            "group_label": spec["label"],
            "color": spec["color"],
            "confidence": confidence,
            "confidence_rank": CONFIDENCE_RANK.get(confidence, 1),
            "sort_order": spec["sort_order"],
            "method": method,
            "classification_signals": signals[:8],
            "explanation": explanation,
            "product_category": product_category or "unknown",
            "vendor_family": vendor_family or "unknown",
            "entity_role": str(fingerprint.get("role") or ""),
            "entity_kind": "network" if str(item.get("bssid") or "").strip() else "client",
            "status": "CLASSIFIED" if group != "UNKNOWN" else "INCONCLUSIVE",
        }

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        deduped: List[str] = []
        seen = set()
        for value in values:
            cleaned = str(value or "").strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            deduped.append(cleaned)
        return deduped
