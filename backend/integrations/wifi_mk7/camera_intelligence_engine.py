from __future__ import annotations

from typing import Any, Dict, List

from backend.integrations.wifi_mk7.camera_signature_database import (
    CAMERA_SIGNATURE_DATABASE,
    CAMERA_VENDOR_BUCKETS,
    IGNORE_MAC_PREFIXES,
    NEGATIVE_VENDOR_BIAS,
    NON_CAMERA_SIBLING_HINTS,
    load_lab_camera_profiles,
    match_keywords,
)


class CameraIntelligenceEngine:
    def __init__(self) -> None:
        self.signature_database = [*CAMERA_SIGNATURE_DATABASE, *load_lab_camera_profiles()]

    def score(self, item: Dict[str, Any], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        mac = str(item.get("mac") or item.get("bssid") or "").lower()
        if any(mac.startswith(prefix.rstrip("*")) for prefix in IGNORE_MAC_PREFIXES):
            return {
                "detected": False,
                "device_type": None,
                "confidence": 0.0,
                "confidence_tier": "LOW",
                "risk": "LOW",
                "classification": "Not camera",
                "ui_label": "ignore_broadcast_multicast",
                "behavior": "Ignored non-endpoint address",
                "score": 0.0,
                "indicators": ["broadcast or multicast address"],
                "components": {"behavior": 0.0, "traffic_shape": 0.0, "tls_signature": 0.0, "discovery": 0.0, "vendor": 0.0},
                "matched_families": [],
                "vendor_bucket": "camera_vendor_generic_low_confidence",
            }

        vendor = str(item.get("vendor") or "").lower()
        identity_text = self._identity_text(item, fingerprint)
        flow = dict(item.get("flow_metrics") or {})
        service = dict(item.get("service_exposure") or {})
        signature_matches = self._signature_matches(item, identity_text)
        role = str(fingerprint.get("role") or "")
        family = str(fingerprint.get("device_family") or "").lower()
        is_infrastructure_family = family in {"isp-cpe", "router", "extender", "mesh"}
        associated_bssid = str(item.get("associated_bssid") or "").lower()
        has_real_association = bool(associated_bssid and associated_bssid != "ff:ff:ff:ff:ff:ff")
        traffic_pattern = str(item.get("traffic_pattern") or "mixed")
        vendor_bucket = self._vendor_bucket(vendor)
        sibling_penalty, sibling_reason = self._non_camera_sibling_penalty(vendor, identity_text)

        behavior_score = 0.0
        traffic_score = 0.0
        tls_score = 0.0
        discovery_score = 0.0
        vendor_score = 0.0
        indicators: List[str] = []

        rssi_variance = float(item.get("rssi_variance_db") or 0.0)
        probe_count = int(item.get("probe_request_count") or 0)
        mobility_class = str(item.get("mobility_class") or "static")
        historical_captures = int(item.get("historical_captures") or 0)
        associated = has_real_association
        temporal_confidence = min(0.2, (historical_captures * 0.03))
        if mobility_class == "static" and rssi_variance <= 6.0:
            behavior_score += 8
            indicators.append("static RSSI profile")
        if probe_count == 0:
            behavior_score += 6
            indicators.append("no probe behavior")
        if associated:
            behavior_score += 3
            indicators.append("persistent AP association")
        if historical_captures >= 3:
            behavior_score += 3
            indicators.append("persistent observation")
        if historical_captures >= 5:
            behavior_score += 2
            indicators.append("long-term persistence")
        if signature_matches["static_profile"]:
            behavior_score += 2
        behavior_score = min(20.0, behavior_score)
        if traffic_pattern == "probe-bursty" or probe_count >= 3:
            behavior_score = max(0.0, behavior_score - 8)
            indicators.append("probe-heavy behavior penalty")

        uplink_ratio = float(flow.get("uplink_ratio") or 0.0)
        duration = float(flow.get("duration_seconds") or 0.0)
        packet_rate = float(flow.get("packet_rate_pps") or 0.0)
        bitrate_variance = float(flow.get("bitrate_variance") or 0.0)
        total_packets = int(flow.get("total_packets") or 0)
        total_bytes = int(flow.get("total_bytes") or 0)
        avg_frame_len = float(item.get("avg_frame_len") or 0.0)
        has_real_stream_flow = bool(total_packets >= 12 and total_bytes >= 1600 and duration >= 20.0)
        if has_real_stream_flow and uplink_ratio >= 0.6:
            traffic_score += 10
            indicators.append("uplink-dominant traffic")
        if flow.get("constant_bitrate"):
            traffic_score += 10
            indicators.append("constant bitrate flow")
        if flow.get("long_lived_flow"):
            traffic_score += 6
            indicators.append("long-lived flow")
        if has_real_stream_flow and 800 <= avg_frame_len <= 1500:
            traffic_score += 4
            indicators.append("large streaming frame size")
        if has_real_stream_flow and packet_rate >= 2.0 and bitrate_variance <= 0.35:
            traffic_score += 4
            indicators.append("low-jitter packet cadence")
        if signature_matches["stream_profile"] and has_real_stream_flow and uplink_ratio >= 0.55:
            traffic_score += 4
            indicators.append("signature database streaming profile match")
        traffic_score = min(30.0, traffic_score)
        if role == "AP" and str(item.get("traffic_pattern") or "") == "broadcast-heavy":
            traffic_score = max(0.0, traffic_score - 10)
            indicators.append("AP broadcast penalty")

        if signature_matches["tls_hits"]:
            tls_score += 18
            indicators.append("camera/cloud TLS signature")
        if any(token in identity_text for token in ("camera", "ipc", "ipcam")):
            tls_score += 7
            indicators.append("camera-oriented identity text")
        if any(match.get("detection_class") == "cloud_locked" for match in signature_matches["families"]):
            tls_score += 4
            indicators.append("cloud-locked camera family profile")
        tls_score = min(25.0, tls_score)

        if signature_matches["discovery_hits"]:
            discovery_score += 10
            indicators.append("camera discovery signal")

        if signature_matches["vendor_hits"]:
            vendor_score += 12
            indicators.append("known camera vendor")
        elif signature_matches["identity_hits"]:
            vendor_score += 8
            indicators.append("camera naming signature")
        if bool(item.get("wps_primary_device_camera")):
            vendor_score += 3
            indicators.append("WPS primary device camera type")
        if signature_matches["confidence_bias"]:
            vendor_score += min(3, max(0, int(signature_matches["confidence_bias"] / 5)))
        if any(bias in vendor for bias in NEGATIVE_VENDOR_BIAS):
            vendor_score -= 6
            indicators.append("negative vendor bias")
        if vendor_bucket == "camera_vendor_conditional" and role == "AP" and not any((signature_matches["tls_hits"], signature_matches["discovery_hits"], bool(item.get("wps_primary_device_camera")), family == "camera")):
            vendor_score -= 6
            indicators.append("conditional vendor without camera evidence")
        if vendor_bucket == "camera_vendor_generic_low_confidence":
            vendor_score -= 4
            indicators.append("generic vendor penalty")
        if sibling_penalty:
            vendor_score -= sibling_penalty
            indicators.append(sibling_reason)
        vendor_score = min(15.0, vendor_score)
        vendor_score = max(0.0, vendor_score)

        has_protocol_evidence = bool(signature_matches["tls_hits"] or signature_matches["discovery_hits"])
        has_identity_evidence = bool(signature_matches["identity_hits"] or item.get("wps_primary_device_camera"))
        has_camera_evidence = bool(has_protocol_evidence or has_identity_evidence)
        score = behavior_score + traffic_score + tls_score + discovery_score + vendor_score + (temporal_confidence * 20.0)
        if role == "AP":
            if is_infrastructure_family and not has_camera_evidence:
                score = min(score, 18.0)
                indicators.append("infrastructure suppression")
            elif family != "camera" and not has_camera_evidence:
                score = min(score, 26.0)
                indicators.append("AP without camera evidence")
        if role != "AP" and probe_count > 0 and not has_camera_evidence and not flow.get("long_lived_flow"):
            score = min(score, 24.0)
            indicators.append("probe-only client suppression")
        if traffic_pattern == "probe-bursty" and role != "AP":
            score = min(score, 28.0)
        if score >= 80.0 and any(match.get("detection_class") == "local_open" for match in signature_matches["families"]):
            classification = "Confirmed camera"
            ui_label = "confirmed_camera_local"
        elif score >= 60.0:
            classification = "Likely camera"
            ui_label = "likely_camera_cloud"
        elif score >= 40.0:
            classification = "Possible stream device"
            ui_label = "possible_stream_device"
        elif role == "AP" and (signature_matches["vendor_hits"] or signature_matches["identity_hits"]) and any((signature_matches["tls_hits"], signature_matches["discovery_hits"], family == "camera", bool(item.get("wps_primary_device_camera")))):
            classification = "Camera-capable network"
            ui_label = "camera_capable_network"
        else:
            classification = "Not camera"
            ui_label = "non_camera_static_device" if mobility_class == "static" and probe_count == 0 else "ignore_broadcast_multicast"

        detection_mode = "unknown"
        if any(match.get("detection_class") == "local_open" for match in signature_matches["families"]):
            detection_mode = "local_camera"
        elif any(match.get("detection_class") == "cloud_locked" for match in signature_matches["families"]):
            detection_mode = "cloud_camera"
        elif any(match.get("detection_class") == "hybrid" for match in signature_matches["families"]):
            detection_mode = "hybrid_camera"

        family_match = ""
        family_match_confidence = "NONE"
        if signature_matches["families"]:
            first_family = signature_matches["families"][0]
            family_match = str(first_family.get("family") or "")
            evidence_strength = 0
            if signature_matches["vendor_hits"]:
                evidence_strength += 1
            if signature_matches["identity_hits"]:
                evidence_strength += 1
            if signature_matches["tls_hits"]:
                evidence_strength += 1
            if signature_matches["discovery_hits"]:
                evidence_strength += 1
            if evidence_strength >= 3:
                family_match_confidence = "HIGH"
            elif evidence_strength >= 2:
                family_match_confidence = "MEDIUM"
            else:
                family_match_confidence = "LOW"

        vendor_explainer = ""
        if signature_matches["families"]:
            family = signature_matches["families"][0]
            family_name = str(family.get("family") or "camera family")
            detection_class = str(family.get("detection_class") or "hybrid")
            if detection_class == "cloud_locked" and not signature_matches["tls_hits"]:
                vendor_explainer = f"{family_name} matched but no cloud TLS evidence was retained this run."
            elif detection_class == "local_open" and not any((signature_matches["discovery_hits"], signature_matches["tls_hits"])):
                vendor_explainer = f"{family_name} matched but no local protocol evidence was retained this run."
            else:
                vendor_explainer = f"{family_name} matched with {detection_class} camera profile."
        if sibling_reason and not any((signature_matches["tls_hits"], signature_matches["discovery_hits"], signature_matches["identity_hits"])):
            vendor_explainer = f"{vendor_explainer} {sibling_reason}." if vendor_explainer else sibling_reason.capitalize() + "."

        return {
            "detected": score >= 60.0,
            "device_type": "WiFi Camera" if score >= 40.0 else None,
            "confidence": round(min(0.98, score / 100.0), 2),
            "camera_confidence_score": round(min(100.0, score), 1),
            "confidence_tier": self._confidence_tier(score / 100.0),
            "risk": "HIGH" if score >= 60.0 else ("MEDIUM" if score >= 40.0 else "LOW"),
            "classification": classification,
            "ui_label": ui_label,
            "behavior": "Streaming profile" if traffic_score >= 18 else "No strong streaming profile",
            "score": round(score, 1),
            "indicators": indicators[:8],
            "components": {
                "behavior": round(behavior_score, 1),
                "traffic_shape": round(traffic_score, 1),
                "tls_signature": round(tls_score, 1),
                "discovery": round(discovery_score, 1),
                "vendor": round(vendor_score, 1),
            },
            "matched_families": [match["family"] for match in signature_matches["families"][:6]],
            "family_match": family_match,
            "family_match_confidence": family_match_confidence,
            "vendor_bucket": vendor_bucket,
            "detection_mode": detection_mode,
            "temporal_confidence": round(temporal_confidence, 2),
            "vendor_explainer": vendor_explainer,
            "audit": {
                "vendor_hits": list(signature_matches["vendor_hits"][:6]),
                "identity_hits": list(signature_matches["identity_hits"][:6]),
                "tls_hits": list(signature_matches["tls_hits"][:6]),
                "discovery_hits": list(signature_matches["discovery_hits"][:6]),
                "traffic_pattern": traffic_pattern,
                "mobility_class": mobility_class,
                "associated": associated,
                "historical_captures": historical_captures,
                "uplink_ratio": round(uplink_ratio, 2),
                "long_lived_flow": bool(flow.get("long_lived_flow")),
                "total_packets": total_packets,
                "sibling_penalty": sibling_penalty,
            },
        }

    @staticmethod
    def _confidence_tier(value: float) -> str:
        if value >= 0.8:
            return "HIGH"
        if value >= 0.5:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _identity_text(item: Dict[str, Any], fingerprint: Dict[str, Any]) -> str:
        parts = [
            str(item.get("ssid") or ""),
            " ".join(item.get("last_ssids") or []),
            str(item.get("historical_identity_hint") or ""),
            " ".join(item.get("related_identity_hints") or []),
            str(item.get("wps_manufacturer") or ""),
            str(item.get("wps_model_name") or ""),
            str(item.get("wps_device_name") or ""),
            str(item.get("vendor") or ""),
            str((fingerprint or {}).get("device_type") or ""),
            " ".join(item.get("dhcp_hostnames") or []),
            " ".join(item.get("dhcp_vendor_class_ids") or []),
            " ".join(item.get("related_hostnames") or []),
            " ".join(item.get("related_domains") or []),
            " ".join(item.get("mdns_service_instances") or []),
            " ".join(item.get("quic_server_names") or []),
            " ".join(item.get("tls_certificate_subjects") or []),
            " ".join(item.get("tls_subject_alt_names") or []),
        ]
        return " ".join(filter(None, parts)).lower()

    def _signature_matches(self, item: Dict[str, Any], identity_text: str) -> Dict[str, Any]:
        tls_text = " ".join(
            [
                *[str(value or "").lower() for value in item.get("tls_server_names") or []],
                *[str(value or "").lower() for value in item.get("quic_server_names") or []],
                *[str(value or "").lower() for value in item.get("tls_subject_alt_names") or []],
                *[str(value or "").lower() for value in item.get("related_domains") or []],
            ]
        )
        discovery_text = " ".join(
            [
                *[str(value or "").lower() for value in item.get("mdns_ptr_names") or []],
                *[str(value or "").lower() for value in item.get("related_services") or []],
                *[str(value or "").lower() for value in item.get("http_hosts") or []],
                *[str(value or "").lower() for value in item.get("http_uris") or []],
                *[str(value or "").lower() for value in item.get("rtsp_urls") or []],
                *[str(value or "").lower() for value in item.get("rtsp_requests") or []],
                *[str(value or "").lower() for value in item.get("dns_query_names") or []],
                *[str(value or "").lower() for value in item.get("related_hostnames") or []],
                *[str(value or "").lower() for value in item.get("dhcp_hostnames") or []],
            ]
        )
        vendor = str(item.get("vendor") or "").lower()
        families: List[Dict[str, Any]] = []
        family_scores: Dict[str, int] = {}
        family_evidence: Dict[str, Dict[str, Any]] = {}
        vendor_hits = []
        identity_hits = []
        tls_hits = []
        discovery_hits = []

        for signature in self.signature_database:
            local_vendor_hits = match_keywords(vendor, signature.get("oui_keywords") or [])
            local_identity_hits = match_keywords(identity_text, [*(signature.get("hostname_keywords") or []), *(signature.get("ssid_keywords") or []), *(signature.get("cert_keywords") or [])])
            local_tls_hits = match_keywords(tls_text, signature.get("tls_sni_keywords") or [])
            local_discovery_hits = match_keywords(discovery_text, signature.get("mdns_ssdp_keywords") or [])
            if any((local_vendor_hits, local_identity_hits, local_tls_hits, local_discovery_hits)):
                signature_key = str(signature.get("family") or "")
                score = (
                    (len(local_vendor_hits) * 2)
                    + (len(local_identity_hits) * 3)
                    + (len(local_tls_hits) * 4)
                    + (len(local_discovery_hits) * 4)
                    + int(signature.get("confidence_bias") or 0)
                )
                family_scores[signature_key] = score
                family_evidence[signature_key] = {
                    "vendor_hits": local_vendor_hits,
                    "identity_hits": local_identity_hits,
                    "tls_hits": local_tls_hits,
                    "discovery_hits": local_discovery_hits,
                }
                families.append(signature)
                vendor_hits.extend(local_vendor_hits)
                identity_hits.extend(local_identity_hits)
                tls_hits.extend(local_tls_hits)
                discovery_hits.extend(local_discovery_hits)
        families = sorted(
            families,
            key=lambda signature: family_scores.get(str(signature.get("family") or ""), 0),
            reverse=True,
        )

        return {
            "families": families,
            "vendor_hits": vendor_hits,
            "identity_hits": identity_hits,
            "tls_hits": tls_hits,
            "discovery_hits": discovery_hits,
            "family_scores": family_scores,
            "family_evidence": family_evidence,
            "confidence_bias": max([int(signature.get("confidence_bias") or 0) for signature in families], default=0),
            "stream_profile": any(bool((signature.get("traffic_profile") or {}).get("long_lived_flows")) and str((signature.get("traffic_profile") or {}).get("uplink_bias") or "") == "high" for signature in families),
            "static_profile": any(bool((signature.get("traffic_profile") or {}).get("static_rssi")) for signature in families),
        }

    @staticmethod
    def _vendor_bucket(vendor: str) -> str:
        for bucket, keywords in CAMERA_VENDOR_BUCKETS.items():
            if any(keyword in vendor for keyword in keywords):
                return bucket
        return "camera_vendor_generic_low_confidence"

    @staticmethod
    def _non_camera_sibling_penalty(vendor: str, identity_text: str) -> tuple[float, str]:
        lowered_vendor = str(vendor or "").lower()
        lowered_identity = str(identity_text or "").lower()
        for vendor_key, hints in NON_CAMERA_SIBLING_HINTS.items():
            if vendor_key in lowered_vendor and any(hint in lowered_identity for hint in hints):
                return 8.0, f"non-camera sibling profile for {vendor_key}"
        return 0.0, ""
