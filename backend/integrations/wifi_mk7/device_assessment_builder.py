from __future__ import annotations

from typing import Any, Dict, List


class DeviceAssessmentBuilder:
    def build(
        self,
        item: Dict[str, Any],
        *,
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
        behavior: Dict[str, Any],
        auth_evidence: Dict[str, Any] | None,
        risk: Dict[str, Any],
        stable_fingerprint: Dict[str, Any],
    ) -> Dict[str, Any]:
        sections = {
            "identity": self._identity_section(item, fingerprint, services, camera),
            "network_behavior": self._network_behavior_section(item, services, behavior, stable_fingerprint),
            "local_exposure": self._local_exposure_section(item, services, camera),
            "streaming_behavior": self._streaming_behavior_section(item, services, camera, behavior, auth_evidence or {}),
        }
        confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for section in sections.values():
            confidence_counts[str(section.get("confidence") or "LOW")] += 1
        overall_confidence = "HIGH" if confidence_counts["HIGH"] >= 2 else ("MEDIUM" if confidence_counts["HIGH"] or confidence_counts["MEDIUM"] >= 2 else "LOW")
        return {
            "version": "v1",
            "overall_confidence": overall_confidence,
            "summary": self._assessment_summary(sections, camera, risk),
            "sections": sections,
        }

    def _answer(
        self,
        key: str,
        question: str,
        value: str,
        *,
        confidence: str = "LOW",
        evidence: List[str] | None = None,
        unknown_reason: str = "",
    ) -> Dict[str, Any]:
        return {
            "key": key,
            "question": question,
            "value": value,
            "confidence": confidence,
            "evidence": list(evidence or []),
            "unknown_reason": unknown_reason,
        }

    def _section(self, title: str, answers: List[Dict[str, Any]], summary: str) -> Dict[str, Any]:
        known_answers = [answer for answer in answers if str(answer.get("value") or "").upper() not in {"UNKNOWN", "--"}]
        section_confidence = "HIGH" if len(known_answers) >= max(3, len(answers) // 2) else ("MEDIUM" if known_answers else "LOW")
        return {
            "title": title,
            "summary": summary,
            "confidence": section_confidence,
            "answers": answers,
        }

    def _identity_section(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
    ) -> Dict[str, Any]:
        identity_hints = list(services.get("identity_hints") or [])
        hostnames = list(item.get("dhcp_hostnames") or [])
        mdns_ptr = list(item.get("mdns_ptr_names") or [])
        mdns_instances = list(item.get("mdns_service_instances") or [])
        vendor = str(item.get("vendor") or "Unknown")
        mac = str(item.get("mac") or item.get("bssid") or "--")
        family = str(camera.get("family_match") or fingerprint.get("device_family") or "unknown")
        advertised_services = sorted(set([*list(services.get("protocols") or []), *list(services.get("services") or [])]))[:6]
        advertised_text = " ".join([*hostnames, *identity_hints, *mdns_ptr, *mdns_instances]).lower()
        brand_revealed = any(token in advertised_text for token in ("hik", "dahua", "reolink", "axis", "arlo", "ring", "tapo", "nest", "wyze", "eufy"))
        camera_revealed = "camera" in advertised_text or "cam" in advertised_text or bool(item.get("wps_primary_device_camera"))
        answers = [
            self._answer(
                "mac_vendor",
                "What is the MAC address and vendor?",
                f"{mac} · {vendor}",
                confidence="HIGH" if mac != "--" and vendor not in {"", "Unknown", "--"} else "MEDIUM",
                evidence=[str(item.get("vendor_country") or item.get("vendor_country_code") or "vendor geography unavailable")],
            ),
            self._answer(
                "mac_randomization",
                "Does the device change MAC?",
                "UNKNOWN",
                confidence="LOW",
                evidence=[f"{int(item.get('historical_captures') or 0)} historical captures retained"],
                unknown_reason="Current model tracks observed identity history but does not yet compute MAC rotation across sessions.",
            ),
            self._answer(
                "hostname_identity",
                "What hostname or identity does it advertise?",
                ", ".join([*hostnames[:3], *identity_hints[:3]]) or "UNKNOWN",
                confidence="HIGH" if hostnames or identity_hints else "LOW",
                evidence=[*(hostnames[:2] or []), *(mdns_ptr[:2] or [])],
                unknown_reason="" if hostnames or identity_hints else "No DHCP or mDNS hostname retained.",
            ),
            self._answer(
                "hostname_reveals_camera",
                "Does the hostname reveal camera, brand, or user information?",
                "YES" if (brand_revealed or camera_revealed) else ("NO" if hostnames or identity_hints or mdns_ptr else "UNKNOWN"),
                confidence="MEDIUM" if (hostnames or identity_hints or mdns_ptr) else "LOW",
                evidence=[value for value in [*hostnames[:2], *identity_hints[:2], *mdns_ptr[:2]] if value],
                unknown_reason="" if (hostnames or identity_hints or mdns_ptr) else "No retained hostname-like evidence.",
            ),
            self._answer(
                "service_advertisement",
                "Does it broadcast mDNS / SSDP / UPnP style services?",
                ", ".join(advertised_services) or "UNKNOWN",
                confidence="MEDIUM" if advertised_services else "LOW",
                evidence=[*mdns_ptr[:2], *mdns_instances[:2], *(services.get("protocols") or [])[:2]],
                unknown_reason="" if advertised_services else "No passive service advertisements retained.",
            ),
            self._answer(
                "self_identification",
                "Does it identify as camera, IoT, or generic device?",
                f"{fingerprint.get('device_type') or 'Unknown'} · family {family}",
                confidence=str(fingerprint.get("confidence_tier") or "LOW"),
                evidence=[str(fingerprint.get("behavior_profile") or "limited fingerprint evidence"), str(camera.get("classification") or "camera classification unavailable")],
            ),
        ]
        return self._section(
            "Identity & Fingerprinting",
            answers,
            f"Observed identity leans {fingerprint.get('device_type') or 'unknown'} with family {family}.",
        )

    def _network_behavior_section(
        self,
        item: Dict[str, Any],
        services: Dict[str, Any],
        behavior: Dict[str, Any],
        stable_fingerprint: Dict[str, Any],
    ) -> Dict[str, Any]:
        domains = list((stable_fingerprint.get("recurring_domains") or {}).keys())[:6]
        destination_ips = list((stable_fingerprint.get("recurring_destination_ips") or {}).keys())[:6]
        cloud_endpoints = list(services.get("cloud_endpoints") or [])[:6]
        long_lived = bool((item.get("flow_metrics") or {}).get("long_lived_flow"))
        uplink_ratio = float(((item.get("flow_metrics") or {}).get("uplink_ratio") or 0.0))
        periodic = str(item.get("traffic_pattern") or "") == "periodic"
        answers = [
            self._answer(
                "resolved_domains",
                "What domains does it resolve or recur against?",
                ", ".join(domains) or "UNKNOWN",
                confidence="MEDIUM" if domains else "LOW",
                evidence=[*domains[:3], *cloud_endpoints[:2]],
                unknown_reason="" if domains else "No recurring domain profiles retained.",
            ),
            self._answer(
                "cloud_dependencies",
                "Does it connect to vendor or cloud endpoints?",
                ", ".join(cloud_endpoints) or ("YES" if str(services.get("summary") or "").lower().find("cloud") >= 0 else "UNKNOWN"),
                confidence="MEDIUM" if cloud_endpoints else "LOW",
                evidence=[services.get("summary") or "No cloud summary retained"],
                unknown_reason="" if cloud_endpoints else "No cloud endpoint hostnames retained.",
            ),
            self._answer(
                "persistent_connections",
                "Does it maintain persistent or long-lived connections?",
                "YES" if long_lived else ("LIKELY" if periodic else "UNKNOWN"),
                confidence="MEDIUM" if long_lived or periodic else "LOW",
                evidence=[behavior.get("flow_summary") or "flow summary unavailable", f"uplink ratio {round(uplink_ratio, 2)}"],
                unknown_reason="" if long_lived or periodic else "No long-lived or periodic flow signal retained.",
            ),
            self._answer(
                "idle_behavior",
                "Does it communicate while idle or powered but unused?",
                "LIKELY" if periodic or int(item.get("historical_captures") or 0) >= 3 else "UNKNOWN",
                confidence="MEDIUM" if periodic else "LOW",
                evidence=[behavior.get("summary") or "behavior unavailable", f"{int(item.get('historical_captures') or 0)} historical captures"],
                unknown_reason="" if periodic else "Requires scenario comparison against known idle windows.",
            ),
            self._answer(
                "retry_behavior",
                "Does it retry connections aggressively?",
                "NO" if int(item.get("retry_count") or 0) == 0 else ("YES" if int(item.get("retry_count") or 0) >= 3 else "LIKELY"),
                confidence="MEDIUM",
                evidence=[f"{int(item.get('retry_count') or 0)} retries", f"{len(destination_ips)} recurring destination IPs"],
            ),
        ]
        return self._section(
            "Network Behavior",
            answers,
            "Behavioral answers come from recurring domains, cloud endpoints, and passive flow shape.",
        )

    def _local_exposure_section(
        self,
        item: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocols = set(services.get("protocols") or [])
        inventory = list(services.get("service_inventory") or [])
        inventory_text = " ".join(
            " ".join([str(entry.get("service") or ""), str(entry.get("detail") or ""), str(entry.get("source") or "")]).lower()
            for entry in inventory
        )
        has_http = "HTTP" in protocols or "http" in inventory_text
        has_tls = "TLS" in protocols or "https" in inventory_text
        has_rtsp = "RTSP" in protocols or "rtsp" in inventory_text
        has_onvif = "ONVIF" in protocols or "onvif" in inventory_text
        has_telnet = "telnet" in inventory_text
        has_ssh = "ssh" in inventory_text
        weak_auth = any(token in inventory_text for token in ("basic", "digest", "unauth", "open"))
        discovery = any(token in protocols for token in ("mDNS", "SSDP/UPnP", "ONVIF"))
        answers = [
            self._answer(
                "exposed_services",
                "What local services are visible?",
                ", ".join(sorted(protocols)) or "UNKNOWN",
                confidence="HIGH" if protocols else "LOW",
                evidence=[services.get("summary") or "No service summary retained"],
                unknown_reason="" if protocols else "No passive service exposure retained.",
            ),
            self._answer(
                "camera_protocols",
                "Does it expose HTTP / HTTPS / RTSP / ONVIF?",
                ", ".join([label for label, enabled in (("HTTP", has_http), ("HTTPS/TLS", has_tls), ("RTSP", has_rtsp), ("ONVIF", has_onvif)) if enabled]) or "NO",
                confidence="HIGH" if any((has_http, has_tls, has_rtsp, has_onvif)) else "MEDIUM",
                evidence=[*(services.get("protocols") or [])[:4], *(services.get("services") or [])[:3]],
            ),
            self._answer(
                "admin_protocols",
                "Does it expose Telnet / SSH or other admin-style services?",
                ", ".join([label for label, enabled in (("Telnet", has_telnet), ("SSH", has_ssh)) if enabled]) or "NO",
                confidence="MEDIUM",
                evidence=[entry.get("detail") or entry.get("service") or "--" for entry in inventory[:3]],
            ),
            self._answer(
                "local_discovery",
                "Does it respond to local discovery scans or service advertisements?",
                "YES" if discovery else "UNKNOWN",
                confidence="MEDIUM" if discovery else "LOW",
                evidence=[*(services.get("protocols") or [])[:3], *(services.get("identity_hints") or [])[:2]],
                unknown_reason="" if discovery else "No mDNS / SSDP / ONVIF discovery evidence retained.",
            ),
            self._answer(
                "local_control",
                "Does the evidence suggest local access or control without the app?",
                "LIKELY" if any((has_rtsp, has_onvif, has_http)) else "UNKNOWN",
                confidence="MEDIUM" if any((has_rtsp, has_onvif, has_http)) else "LOW",
                evidence=[camera.get("behavior") or "camera behavior unavailable", services.get("summary") or "No protocol summary retained"],
                unknown_reason="" if any((has_rtsp, has_onvif, has_http)) else "No local-access protocol retained.",
            ),
            self._answer(
                "weak_auth",
                "Are any visible services unauthenticated or weakly authenticated?",
                "LIKELY" if weak_auth else "UNKNOWN",
                confidence="LOW" if weak_auth else "LOW",
                evidence=[entry.get("detail") or entry.get("service") or "--" for entry in inventory[:4]],
                unknown_reason="" if weak_auth else "Passive evidence does not currently prove auth strength.",
            ),
        ]
        return self._section(
            "Local Network Exposure",
            answers,
            "Local exposure is derived from passive protocol and service inventory evidence only.",
        )

    def _streaming_behavior_section(
        self,
        item: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
        behavior: Dict[str, Any],
        auth_evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocol_conf = dict(services.get("protocol_confidence") or {})
        rtsp_conf = int(protocol_conf.get("RTSP") or 0)
        http_conf = int(protocol_conf.get("HTTP") or 0)
        tls_conf = int(protocol_conf.get("TLS") or 0)
        long_lived = bool((item.get("flow_metrics") or {}).get("long_lived_flow"))
        traffic_pattern = str(item.get("traffic_pattern") or "")
        stream_like = traffic_pattern == "steady-stream" or long_lived or rtsp_conf >= 40
        cloud_like = bool(services.get("cloud_endpoints")) and tls_conf >= 20
        local_like = rtsp_conf >= 20 or http_conf >= 20
        answers = [
            self._answer(
                "stream_presence",
                "Is there evidence of active streaming behavior?",
                "LIKELY" if stream_like else ("UNKNOWN" if tls_conf or http_conf or rtsp_conf else "NO"),
                confidence="MEDIUM" if stream_like else "LOW",
                evidence=[behavior.get("flow_summary") or "flow summary unavailable", f"RTSP {rtsp_conf} / HTTP {http_conf} / TLS {tls_conf}"],
            ),
            self._answer(
                "stream_transport",
                "What transport path is visible for video or imaging traffic?",
                "RTSP" if rtsp_conf >= max(http_conf, tls_conf) and rtsp_conf > 0 else ("HTTP" if http_conf > max(rtsp_conf, tls_conf) else ("TLS" if tls_conf > 0 else "UNKNOWN")),
                confidence="MEDIUM" if any((rtsp_conf, http_conf, tls_conf)) else "LOW",
                evidence=[services.get("summary") or "No protocol summary retained"],
                unknown_reason="" if any((rtsp_conf, http_conf, tls_conf)) else "No stream protocol retained.",
            ),
            self._answer(
                "idle_streaming",
                "Does it appear to send data while idle or without user interaction?",
                "LIKELY" if stream_like and traffic_pattern in {"steady-stream", "periodic"} else "UNKNOWN",
                confidence="MEDIUM" if stream_like and traffic_pattern in {"steady-stream", "periodic"} else "LOW",
                evidence=[behavior.get("summary") or "behavior unavailable", f"activity {behavior.get('activity_pattern') or '--'}"],
                unknown_reason="" if stream_like and traffic_pattern in {"steady-stream", "periodic"} else "Needs scenario comparison for idle vs live view.",
            ),
            self._answer(
                "image_extraction",
                "Can the current passive evidence extract images or frames?",
                "NO" if not any((item.get("saved_image_count"), item.get("http_object_count"))) else "YES",
                confidence="HIGH" if any((item.get("saved_image_count"), item.get("http_object_count"))) else "MEDIUM",
                evidence=[f"auth quality {auth_evidence.get('quality') or 'NONE'}", f"saved images {int(item.get('saved_image_count') or 0)}"],
            ),
            self._answer(
                "stream_scope",
                "Does traffic look local, cloud-relayed, or unknown?",
                "local" if local_like and not cloud_like else ("cloud" if cloud_like and not local_like else ("hybrid" if local_like and cloud_like else "UNKNOWN")),
                confidence="MEDIUM" if local_like or cloud_like else "LOW",
                evidence=[*(services.get("cloud_endpoints") or [])[:2], *(services.get("protocols") or [])[:3]],
                unknown_reason="" if local_like or cloud_like else "No retained evidence distinguishes local vs cloud stream path.",
            ),
        ]
        return self._section(
            "Streaming Behavior",
            answers,
            "Streaming answers are conservative and require real protocol or flow evidence; scenario-driven tests are still needed for event behavior.",
        )

    def _assessment_summary(self, sections: Dict[str, Any], camera: Dict[str, Any], risk: Dict[str, Any]) -> str:
        identity = sections["identity"]["confidence"]
        exposure = sections["local_exposure"]["confidence"]
        streaming = sections["streaming_behavior"]["confidence"]
        return (
            f"Assessment v1: identity {identity.lower()}, local exposure {exposure.lower()}, "
            f"streaming {streaming.lower()}, overall camera classification {camera.get('classification') or 'unknown'}, "
            f"risk {risk.get('risk') or 'UNKNOWN'}."
        )
