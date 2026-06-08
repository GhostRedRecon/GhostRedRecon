from __future__ import annotations

from typing import Any, Dict, List, Optional


class LoRaDeviceIntelligenceEngine:
    VERSION = "1.0.0"
    EU868_CENTERS = (867.1, 867.3, 867.5, 867.7, 867.9, 868.1, 868.3, 868.5, 869.525)
    US915_CENTERS = (903.9, 904.1, 904.3, 904.5, 904.7, 904.9, 905.1, 905.3, 923.3)
    ISM433_CENTERS = (433.175, 433.375, 433.775, 433.92)

    def enrich_emitters(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self._enrich_single(emitter) for emitter in (emitters or [])]

    def _enrich_single(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        emitter = dict(emitter or {})

        protocol = str(emitter.get("rf_protocol") or emitter.get("protocol") or "").upper()
        rf_band = str(emitter.get("rf_band") or emitter.get("band") or "").lower()
        center_freq = self._as_float(emitter.get("center_freq_mhz"), emitter.get("frequency_mhz"))
        subghz_profile = str(emitter.get("rf_subghz_profile") or "").lower()

        is_lora = protocol in {"LORA", "LORA_PHY"} or "lora" in subghz_profile or rf_band == "lora"
        is_subghz = is_lora or rf_band in {"subghz", "sub-ghz", "sub_ghz"} or (center_freq is not None and center_freq < 1000.0)
        if not is_subghz:
            return emitter

        observation_count = self._as_int(
            emitter.get("rf_observation_count"),
            emitter.get("observation_count"),
            emitter.get("signal_count"),
            default=0,
        )
        stability = self._as_float(
            emitter.get("rf_signal_stability"),
            emitter.get("signal_stability"),
            default=0.0,
        )
        periodicity = self._as_float(
            emitter.get("rf_burst_periodicity"),
            emitter.get("periodicity"),
        )
        burst_ratio = self._as_float(
            emitter.get("rf_duty_cycle"),
            emitter.get("burst_ratio"),
            default=0.0,
        )
        recurrence = self._as_float(
            emitter.get("burst_recurrence_score"),
            default=0.0,
        )
        frame_confidence = self._as_float(
            emitter.get("rf_frame_confidence"),
            default=0.0,
        )
        temporal_consistency = self._as_float(
            emitter.get("temporal_consistency"),
            default=0.0,
        )
        bandwidth_mhz = self._as_float(
            emitter.get("bandwidth_estimate_mhz"),
            emitter.get("rf_bandwidth_mhz"),
            default=0.0,
        )
        burst_duration_ms = self._as_float(
            emitter.get("burst_duration_ms"),
            emitter.get("frame_burst_duration_ms"),
            default=0.0,
        )
        chirp_detected = bool(emitter.get("rf_chirp_detected"))
        frame_structure = str(emitter.get("rf_frame_structure") or "").lower()
        modulation_hint = str(emitter.get("rf_modulation_hint") or "").lower()
        chirp_hint = self._as_float(emitter.get("spectral_chirp_hint"), default=0.0)
        power = self._as_float(
            emitter.get("avg_power_db"),
            emitter.get("power_db"),
            default=-120.0,
        )
        raw_freqs = list(emitter.get("frequencies") or [])
        if not raw_freqs and isinstance(emitter.get("signals"), list):
            for signal in emitter.get("signals") or []:
                if not isinstance(signal, dict):
                    continue
                freq = self._as_float(signal.get("frequency_mhz"), signal.get("freq_mhz"), default=None)
                if freq is not None:
                    raw_freqs.append(freq)
        freqs = [self._as_float(v, default=None) for v in raw_freqs]
        freqs = [v for v in freqs if v is not None]
        frequency_span = (max(freqs) - min(freqs)) if len(freqs) >= 2 else 0.0
        frequency_count = len(freqs)
        region = self._infer_region(center_freq)
        bandplan, bandplan_confidence = self._infer_bandplan(freqs, center_freq)
        cadence_class = self._classify_cadence(
            periodicity=periodicity,
            burst_ratio=burst_ratio,
            recurrence=recurrence,
            burst_duration_ms=burst_duration_ms,
        )

        role = "unknown"
        confidence = 0.0
        mode = "subghz_general"

        if is_lora:
            mode = "lpwan_uplink"
            if observation_count >= 6 and stability >= 0.65 and power >= -78 and burst_ratio >= 0.40:
                role = "gateway"
                confidence = 0.74
                mode = "lpwan_gateway"
            elif (
                chirp_detected
                or frame_structure == "chirp"
                or modulation_hint == "lora_like"
                or "lora" in subghz_profile
                or (recurrence >= 0.40 and burst_ratio <= 0.35)
                or (periodicity is not None and periodicity >= 0.2 and burst_ratio <= 0.35)
            ):
                role = "end_device"
                confidence = 0.66 + (0.10 if chirp_detected or frame_structure == "chirp" or modulation_hint == "lora_like" else 0.0) + (0.06 if "lora" in subghz_profile or chirp_hint >= 0.20 else 0.0)
                confidence = min(confidence, 0.88)
                mode = "lpwan_endpoint"
        else:
            if recurrence >= 0.45 or (periodicity is not None and periodicity >= 0.2):
                role = "sensor_node"
                confidence = 0.61
                mode = "subghz_periodic_telemetry"
            elif observation_count >= 5 and power >= -72:
                role = "receiver_hub"
                confidence = 0.58
                mode = "subghz_fixed_receiver"

        emitter["subghz_intel_version"] = self.VERSION
        emitter["subghz_profile"] = subghz_profile or ("lora" if is_lora else "generic_subghz")
        emitter["subghz_recurring_like"] = bool(recurrence >= 0.40 or (periodicity is not None and periodicity > 0.0))
        emitter["subghz_recurrence_confidence"] = round(max(recurrence, 0.25 if emitter["subghz_recurring_like"] else 0.0), 4)

        if role == "unknown":
            return emitter

        device_type, device_category, type_confidence, identity_family, identity_evidence = self._infer_device_type(
            is_lora=is_lora,
            role=role,
            mode=mode,
            region=region,
            observation_count=observation_count,
            stability=stability,
            periodicity=periodicity,
            burst_ratio=burst_ratio,
            recurrence=recurrence,
            frame_confidence=frame_confidence,
            temporal_consistency=temporal_consistency,
            bandwidth_mhz=bandwidth_mhz,
            burst_duration_ms=burst_duration_ms,
            chirp_detected=chirp_detected,
            chirp_hint=chirp_hint,
            power=power,
            frequency_span=frequency_span,
            frequency_count=frequency_count,
            bandplan=bandplan,
            cadence_class=cadence_class,
        )

        emitter["lora_role"] = role if is_lora else None
        emitter["lora_role_confidence"] = round(confidence, 4) if is_lora else emitter.get("lora_role_confidence")
        emitter["lora_operating_mode_hint"] = mode if is_lora else emitter.get("lora_operating_mode_hint")
        emitter["lora_device_type_hint"] = device_type if is_lora else emitter.get("lora_device_type_hint")
        emitter["lora_device_type_confidence"] = round(type_confidence, 4) if is_lora else emitter.get("lora_device_type_confidence")
        emitter["lora_network_region"] = region if is_lora else emitter.get("lora_network_region")
        emitter["lora_bandplan"] = bandplan if is_lora else emitter.get("lora_bandplan")
        emitter["lora_bandplan_confidence"] = round(bandplan_confidence, 4) if is_lora else emitter.get("lora_bandplan_confidence")
        emitter["lora_cadence_class"] = cadence_class if is_lora else emitter.get("lora_cadence_class")
        emitter["lora_identity_family"] = identity_family if is_lora else emitter.get("lora_identity_family")
        emitter["lora_identity_evidence"] = list(identity_evidence) if is_lora else emitter.get("lora_identity_evidence")
        raw_mesh_score = self._score_mesh_like(observation_count, periodicity, burst_ratio, chirp_detected, chirp_hint, recurrence)
        raw_meter_score = self._score_meter_like(periodicity, burst_ratio, recurrence, region, stability)
        raw_industrial_score = self._score_industrial_like(stability, recurrence, power, burst_ratio, observation_count)
        raw_gateway_score = self._score_gateway_like(observation_count, stability, power, burst_ratio, frequency_span)
        score_map = self._normalize_family_scores(
            identity_family=identity_family,
            mesh_score=raw_mesh_score,
            meter_score=raw_meter_score,
            industrial_score=raw_industrial_score,
            gateway_score=raw_gateway_score,
        )

        emitter["lora_mesh_like"] = bool(identity_family == "meshtastic_node") if is_lora else emitter.get("lora_mesh_like")
        emitter["lora_meter_like"] = bool(identity_family in {"utility_meter_endpoint", "ami_meter_endpoint", "meter_like_endpoint"}) if is_lora else emitter.get("lora_meter_like")
        emitter["lora_lorawan_like"] = bool(identity_family in {"lorawan_gateway", "lorawan_endpoint"}) if is_lora else emitter.get("lora_lorawan_like")
        emitter["lora_mesh_score"] = round(score_map["mesh"], 4) if is_lora else emitter.get("lora_mesh_score")
        emitter["lora_meter_score"] = round(score_map["meter"], 4) if is_lora else emitter.get("lora_meter_score")
        emitter["lora_industrial_score"] = round(score_map["industrial"], 4) if is_lora else emitter.get("lora_industrial_score")
        emitter["lora_gateway_score"] = round(score_map["gateway"], 4) if is_lora else emitter.get("lora_gateway_score")
        emitter["lora_dwell_span_mhz"] = round(frequency_span, 4) if is_lora else emitter.get("lora_dwell_span_mhz")
        emitter["lora_frequency_count"] = frequency_count if is_lora else emitter.get("lora_frequency_count")
        emitter["subghz_role"] = role
        emitter["subghz_role_confidence"] = round(confidence, 4)
        emitter["subghz_operating_mode_hint"] = mode

        if emitter.get("device_role_hint") is None:
            emitter["device_role_hint"] = role
        if emitter.get("device_role_confidence") is None:
            emitter["device_role_confidence"] = round(confidence, 4)
        if emitter.get("device_type") is None:
            emitter["device_type"] = device_type
        if emitter.get("device_category") is None:
            emitter["device_category"] = device_category
        if emitter.get("product_category_hint") is None:
            emitter["product_category_hint"] = self._product_category(device_type, role, is_lora)
        if emitter.get("product_category_confidence") is None:
            emitter["product_category_confidence"] = round(type_confidence * 0.92, 4)
        if emitter.get("behavior_profile_hint") is None:
            emitter["behavior_profile_hint"] = mode
        if emitter.get("rf_device_class") is None:
            emitter["rf_device_class"] = device_type

        return emitter

    def _infer_device_type(
        self,
        *,
        is_lora: bool,
        role: str,
        mode: str,
        region: str,
        observation_count: int,
        stability: float,
        periodicity: Optional[float],
        burst_ratio: float,
        recurrence: float,
        frame_confidence: float,
        temporal_consistency: float,
        bandwidth_mhz: float,
        burst_duration_ms: float,
        chirp_detected: bool,
        chirp_hint: float,
        power: float,
        frequency_span: float,
        frequency_count: int,
        bandplan: str,
        cadence_class: str,
    ) -> tuple[str, str, float, str, list[str]]:
        periodicity = periodicity or 0.0
        evidence: list[str] = []
        phy_confidence = self._estimate_lora_phy_confidence(
            chirp_detected=chirp_detected,
            chirp_hint=chirp_hint,
            frame_confidence=frame_confidence,
            temporal_consistency=temporal_consistency,
            bandwidth_mhz=bandwidth_mhz,
            burst_duration_ms=burst_duration_ms,
            recurrence=recurrence,
        )
        if region != "unknown":
            evidence.append(f"region:{region}")
        if bandplan != "unknown":
            evidence.append(f"bandplan:{bandplan}")
        if chirp_detected:
            evidence.append("chirp_detected")
        if chirp_hint >= 0.20:
            evidence.append("spectral_chirp")
        if frame_confidence >= 0.55:
            evidence.append("frame_confident")
        if temporal_consistency >= 0.65:
            evidence.append("stable_presence")
        if recurrence >= 0.40:
            evidence.append("recurring")
        if periodicity >= 0.80:
            evidence.append("high_periodicity")
        elif periodicity >= 0.15:
            evidence.append("periodic")
        if burst_ratio <= 0.12:
            evidence.append("low_duty")
        elif burst_ratio >= 0.30:
            evidence.append("active_duty")
        if 0.003 <= bandwidth_mhz <= 0.60:
            evidence.append("narrow_lpwan_bw")
        if burst_duration_ms >= 35.0:
            evidence.append("long_burst")
        if cadence_class != "sporadic":
            evidence.append(f"cadence:{cadence_class}")
        if frequency_span >= 0.4:
            evidence.append("multi_channel_span")
        elif frequency_count <= 2 and frequency_span <= 0.30:
            evidence.append("single_channel_dwell")
        if frequency_span >= 2.0 or frequency_count >= 8:
            evidence.append("wide_dwell_span")

        gateway_like_span = frequency_span >= 1.6 or frequency_count >= 6
        gateway_like_presence = (
            observation_count >= 6
            and stability >= 0.60
            and power >= -82
            and temporal_consistency >= 0.55
        )

        if is_lora and (role == "gateway" or gateway_like_span and gateway_like_presence):
            evidence.append("gateway_like_span")
            if frequency_span >= 0.4 or observation_count >= 8 or bandplan in {"eu868", "us915"}:
                return ("LoRaWAN Gateway", "LPWAN Infrastructure", 0.84, "lorawan_gateway", evidence + ["gateway_role"])
            return ("LoRa Gateway", "LPWAN Infrastructure", 0.74, "lora_gateway", evidence + ["gateway_role"])

        if is_lora and role == "end_device":
            lorawan_like_endpoint = (
                phy_confidence >= 0.62
                and (
                    frequency_span >= 1.0
                    or frequency_count >= 5
                    or recurrence >= 0.45
                )
            )
            utility_meter_like = (
                periodicity >= 0.85
                and burst_ratio <= 0.08
                and recurrence >= 0.55
                and frequency_span <= 0.6
                and frequency_count <= 3
                and burst_duration_ms <= 45.0
                and cadence_class in {"meter_periodic", "telemetry_periodic"}
            )
            mesh_like = (
                phy_confidence >= 0.55
                and 0.12 <= burst_ratio <= 0.45
                and observation_count >= 4
                and 0.12 <= periodicity <= 0.75
                and 1.0 <= frequency_span <= 4.0
                and frequency_count >= 3
            )
            industrial_like = (
                stability >= 0.70
                and recurrence >= 0.25
                and power >= -85
                and temporal_consistency >= 0.55
            )

            if utility_meter_like:
                if bandplan == "eu868" or region == "eu868":
                    return ("Utility Meter Endpoint", "Utility IoT", 0.72, "utility_meter_endpoint", evidence + ["meter_like"])
                if bandplan == "us915" or region == "us915":
                    return ("AMI Meter Endpoint", "Utility IoT", 0.68, "ami_meter_endpoint", evidence + ["meter_like"])
                return ("Meter-Like LoRa Endpoint", "Utility IoT", 0.64, "meter_like_endpoint", evidence + ["meter_like"])
            if mesh_like:
                return ("Meshtastic Node", "Mesh IoT", 0.70, "meshtastic_node", evidence + ["mesh_like"])
            if industrial_like and mode == "lpwan_endpoint":
                return ("Industrial LoRa Sensor", "Industrial IoT", 0.66, "industrial_lora_sensor", evidence + ["industrial_like"])
            if lorawan_like_endpoint:
                return ("LoRa IoT Sensor", "LPWAN Endpoint", 0.62, "lorawan_endpoint", evidence + ["endpoint_like"])
            if bandplan == "ism433" and cadence_class in {"event_driven", "telemetry_periodic"}:
                return ("ISM433 LoRa Sensor", "LPWAN Endpoint", 0.61, "lora_end_device", evidence + ["ism433_endpoint"])
            if phy_confidence >= 0.45:
                return ("LoRa End Device", "LPWAN Endpoint", 0.60, "lora_end_device", evidence + ["endpoint_like"])
            return ("LoRa End Device", "LPWAN Endpoint", 0.58, "lora_end_device", evidence + ["endpoint_like"])

        if role == "sensor_node":
            if periodicity >= 0.85 and burst_ratio <= 0.12:
                return ("Utility Telemetry Node", "Utility IoT", 0.60, "utility_telemetry_node", evidence + ["meter_like"])
            return ("Sub-GHz Sensor Node", "Sub-GHz Telemetry", 0.56, "subghz_sensor_node", evidence + ["sensor_node"])

        if role == "receiver_hub":
            return ("Sub-GHz Receiver Hub", "Sub-GHz Infrastructure", 0.58, "subghz_receiver_hub", evidence + ["receiver_hub"])

        return ("Sub-GHz Device", "Sub-GHz RF Device", 0.50, "subghz_device", evidence)

    def _product_category(self, device_type: str, role: str, is_lora: bool) -> str:
        normalized = str(device_type or "").lower()
        if "gateway" in normalized:
            return "lora_gateway" if is_lora else "subghz_gateway"
        if "meter" in normalized:
            return "utility_meter"
        if "meshtastic" in normalized or "mesh" in normalized:
            return "mesh_node"
        if "industrial" in normalized:
            return "industrial_iot"
        if role == "end_device":
            return "lora_sensor" if is_lora else "subghz_sensor"
        if role == "receiver_hub":
            return "subghz_receiver"
        return "subghz_device"

    @staticmethod
    def _score_mesh_like(
        observation_count: int,
        periodicity: Optional[float],
        burst_ratio: float,
        chirp_detected: bool,
        chirp_hint: float,
        recurrence: float,
    ) -> float:
        periodicity = periodicity or 0.0
        score = 0.0
        if chirp_detected:
            score += 0.20
        if chirp_hint >= 0.35:
            score += 0.20
        if 0.12 <= burst_ratio <= 0.45:
            score += 0.25
        elif burst_ratio < 0.08:
            score -= 0.15
        if 0.12 <= periodicity <= 0.75:
            score += 0.15
        elif periodicity > 0.90:
            score -= 0.10
        if observation_count >= 4:
            score += 0.10
        if 0.20 <= recurrence <= 0.80:
            score += 0.10
        return min(max(score, 0.0), 1.0)

    @staticmethod
    def _score_meter_like(
        periodicity: Optional[float],
        burst_ratio: float,
        recurrence: float,
        region: str,
        stability: float,
    ) -> float:
        periodicity = periodicity or 0.0
        score = 0.0
        if periodicity >= 0.95:
            score += 0.40
        elif periodicity >= 0.85:
            score += 0.25
        elif periodicity >= 0.70:
            score += 0.10
        if burst_ratio <= 0.08:
            score += 0.25
        elif burst_ratio <= 0.15:
            score += 0.10
        if recurrence >= 0.55:
            score += 0.20
        elif recurrence >= 0.40:
            score += 0.10
        if region in {"eu868", "us915"}:
            score += 0.10
        if stability >= 0.70:
            score += 0.05
        return min(score, 1.0)

    @staticmethod
    def _score_industrial_like(
        stability: float,
        recurrence: float,
        power: float,
        burst_ratio: float,
        observation_count: int,
    ) -> float:
        score = 0.0
        if stability >= 0.70:
            score += 0.25
        if recurrence >= 0.25:
            score += 0.25
        if power >= -85:
            score += 0.15
        if 0.05 <= burst_ratio <= 0.30:
            score += 0.15
        if observation_count >= 5:
            score += 0.15
        return min(score, 1.0)

    @staticmethod
    def _score_gateway_like(
        observation_count: int,
        stability: float,
        power: float,
        burst_ratio: float,
        frequency_span: float,
    ) -> float:
        score = 0.0
        if observation_count >= 8:
            score += 0.30
        elif observation_count >= 5:
            score += 0.15
        if stability >= 0.65:
            score += 0.20
        if power >= -78:
            score += 0.15
        if burst_ratio >= 0.40:
            score += 0.15
        if frequency_span >= 0.4:
            score += 0.20
        return min(score, 1.0)

    @staticmethod
    def _estimate_lora_phy_confidence(
        *,
        chirp_detected: bool,
        chirp_hint: float,
        frame_confidence: float,
        temporal_consistency: float,
        bandwidth_mhz: float,
        burst_duration_ms: float,
        recurrence: float,
    ) -> float:
        score = 0.0
        if chirp_detected:
            score += 0.30
        if chirp_hint >= 0.35:
            score += 0.20
        elif chirp_hint >= 0.20:
            score += 0.10
        if frame_confidence >= 0.70:
            score += 0.20
        elif frame_confidence >= 0.45:
            score += 0.10
        if temporal_consistency >= 0.70:
            score += 0.10
        if 0.003 <= bandwidth_mhz <= 0.60:
            score += 0.10
        if burst_duration_ms >= 35.0:
            score += 0.05
        if recurrence >= 0.40:
            score += 0.05
        return min(score, 1.0)

    @staticmethod
    def _normalize_family_scores(
        *,
        identity_family: str,
        mesh_score: float,
        meter_score: float,
        industrial_score: float,
        gateway_score: float,
    ) -> Dict[str, float]:
        scores = {
            "mesh": float(mesh_score),
            "meter": float(meter_score),
            "industrial": float(industrial_score),
            "gateway": float(gateway_score),
        }

        winner_map = {
            "meshtastic_node": "mesh",
            "utility_meter_endpoint": "meter",
            "ami_meter_endpoint": "meter",
            "meter_like_endpoint": "meter",
            "utility_telemetry_node": "meter",
            "industrial_lora_sensor": "industrial",
            "lorawan_gateway": "gateway",
            "lora_gateway": "gateway",
        }
        winner = winner_map.get(str(identity_family or "").strip().lower())
        if winner is None:
            winner = "gateway" if "gateway" in str(identity_family or "").lower() else None

        if winner:
            for key in list(scores.keys()):
                if key == winner:
                    scores[key] = min(1.0, scores[key] + 0.15)
                else:
                    scores[key] *= 0.35
        else:
            # Endpoint-like outcomes should suppress unrelated subtype families.
            scores["mesh"] *= 0.25
            scores["meter"] *= 0.25
            scores["gateway"] *= 0.45
            scores["industrial"] *= 0.55

        return scores

    @staticmethod
    def _infer_region(center_freq: Optional[float]) -> str:
        if center_freq is None:
            return "unknown"
        if 863.0 <= center_freq <= 870.5:
            return "eu868"
        if 902.0 <= center_freq <= 928.0:
            return "us915"
        if 433.0 <= center_freq <= 435.5:
            return "ism433"
        return "unknown"

    def _infer_bandplan(
        self,
        freqs: List[float],
        center_freq: Optional[float],
    ) -> tuple[str, float]:
        points = list(freqs or [])
        if center_freq is not None:
            points.append(center_freq)
        if not points:
            return ("unknown", 0.0)

        scores = {
            "eu868": self._bandplan_score(points, self.EU868_CENTERS, 0.30, 0.65),
            "us915": self._bandplan_score(points, self.US915_CENTERS, 0.30, 0.65),
            "ism433": self._bandplan_score(points, self.ISM433_CENTERS, 0.20, 0.50),
        }
        winner = max(scores, key=scores.get)
        confidence = scores[winner]
        if confidence < 0.30:
            return ("unknown", confidence)
        return (winner, confidence)

    @staticmethod
    def _bandplan_score(points: List[float], centers: tuple[float, ...], exact_tol: float, near_tol: float) -> float:
        score = 0.0
        for point in points:
            distance = min(abs(point - center) for center in centers)
            if distance <= exact_tol:
                score += 0.35
            elif distance <= near_tol:
                score += 0.18
        return min(score, 1.0)

    @staticmethod
    def _classify_cadence(
        *,
        periodicity: Optional[float],
        burst_ratio: float,
        recurrence: float,
        burst_duration_ms: float,
    ) -> str:
        periodicity = periodicity or 0.0
        if periodicity >= 0.88 and recurrence >= 0.55 and burst_ratio <= 0.08 and burst_duration_ms <= 60.0:
            return "meter_periodic"
        if periodicity >= 0.50 and recurrence >= 0.35 and burst_ratio <= 0.18:
            return "telemetry_periodic"
        if burst_ratio >= 0.40 and recurrence >= 0.20:
            return "infrastructure_active"
        if recurrence >= 0.20:
            return "event_driven"
        return "sporadic"

    @staticmethod
    def _as_float(*values: Any, default: Optional[float] = 0.0) -> Optional[float]:
        for value in values:
            try:
                if value is None:
                    continue
                return float(value)
            except Exception:
                continue
        return default

    @staticmethod
    def _as_int(*values: Any, default: int = 0) -> int:
        for value in values:
            try:
                if value is None:
                    continue
                return int(value)
            except Exception:
                continue
        return default
