from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple


def _bucket_band_from_channel(channel: Any) -> str:
    try:
        value = int(channel or 0)
    except Exception:
        value = 0
    if value in {36, 40, 44, 48, 149, 153, 157, 161, 165}:
        return "5.8 GHz"
    if value:
        return "2.4 GHz"
    return "unknown"


def _bucket_band_from_frequency(freq_mhz: Any) -> str:
    try:
        value = float(freq_mhz or 0.0)
    except Exception:
        value = 0.0
    if value >= 5000.0:
        return "5.8 GHz"
    if value >= 2300.0:
        return "2.4 GHz"
    return "unknown"


class EvidenceNormalizer:
    WIFI_FRAME_HINTS = ("beacon", "probe", "action", "management")

    def normalize_wifi(self, rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for item in rows:
            row = dict(item)
            timestamp = float(row.get("timestamp") or time.time())
            channel = row.get("channel")
            ssid = str(row.get("ssid") or "").strip()
            vendor = str(row.get("vendor") or row.get("oui_vendor") or row.get("manufacturer") or "").strip()
            frame_subtype = str(row.get("frame_subtype") or row.get("inventory_kind") or "management")
            bssid = str(row.get("bssid") or row.get("mac") or row.get("associated_bssid") or "").strip().lower()
            hidden = not ssid or ssid == "<hidden>"
            event_id = hashlib.sha1(f"wifi|{timestamp}|{bssid}|{ssid}|{channel}".encode("utf-8")).hexdigest()[:16]
            normalized.append(
                {
                    "event_id": event_id,
                    "kind": "wifi",
                    "timestamp": timestamp,
                    "interface": row.get("interface") or row.get("monitor_interface") or "wlan1mon",
                    "channel": channel,
                    "band": _bucket_band_from_channel(channel),
                    "bssid": bssid or "--",
                    "ssid": ssid or "<hidden>",
                    "hidden": hidden,
                    "rssi_dbm": int(row.get("rssi_dbm") or -95),
                    "frame_subtype": frame_subtype,
                    "oui_vendor": vendor or "Unknown",
                    "recurrence_count": int(row.get("packet_count") or 0),
                    "feature_flags": {
                        "hidden_ssid": hidden,
                        "management_like": any(token in frame_subtype.lower() for token in self.WIFI_FRAME_HINTS),
                        "controller_like": bool(row.get("associated_bssid")),
                        "high_band": _bucket_band_from_channel(channel) == "5.8 GHz",
                    },
                    "raw_evidence_pointer": "wifi/management_frames.jsonl",
                    "raw": row,
                }
            )
        return normalized

    def normalize_sdr(self, rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for item in rows:
            row = dict(item)
            timestamp = float(row.get("timestamp") or time.time())
            center = float(row.get("peak_mhz") or row.get("center_frequency_mhz") or 0.0)
            peak = float(row.get("peak_db") or row.get("amplitude_db") or -110.0)
            profile = str(row.get("profile_key") or row.get("profile") or "sweep")
            event_id = hashlib.sha1(f"sdr|{timestamp}|{center}|{peak}|{profile}".encode("utf-8")).hexdigest()[:16]
            normalized.append(
                {
                    "event_id": event_id,
                    "kind": "sdr",
                    "timestamp": timestamp,
                    "profile": profile,
                    "frequency_range": row.get("range") or row.get("frequency_range") or "drone-band",
                    "center_frequency_mhz": center,
                    "band": _bucket_band_from_frequency(center),
                    "amplitude_db": peak,
                    "local_noise_floor_db": float(row.get("noise_floor_db") or -92.0),
                    "anomaly_delta_db": max(0.0, peak - float(row.get("noise_floor_db") or -92.0)),
                    "burst_metrics": {
                        "peak_db": peak,
                        "density": float(row.get("burst_density") or 0.0),
                        "recurrence": float(row.get("burst_recurrence") or 0.0),
                    },
                    "cluster_id": str(row.get("row_id") or event_id),
                    "rolling_persistence": float(row.get("rolling_persistence") or 0.0),
                    "raw_evidence_pointer": "sdr/events.jsonl",
                    "raw": row,
                }
            )
        return normalized


class AnomalyScoringService:
    DJI_HINTS = ("dji", "neo", "avic", "mavic", "mini", "phantom", "inspire", "air ")
    REMOTE_ID_HINTS = ("rid", "remote id", "opendroneid", "uas", "uav", "drone", "astm")
    INFRA_HINTS = ("movistar", "vodafone", "orange", "router", "ap", "tplink", "tp-link", "netgear", "asus")

    def score_wifi(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        ssid = str(event.get("ssid") or "").lower()
        vendor = str(event.get("oui_vendor") or "").lower()
        recurrence = int(event.get("recurrence_count") or 0)
        rssi = int(event.get("rssi_dbm") or -95)
        score = 0
        rationale: List[str] = []
        if any(token in ssid or token in vendor for token in self.DJI_HINTS):
            score += 34
            rationale.append("DJI-family Wi-Fi identity hint.")
        if any(token in ssid or token in vendor for token in self.REMOTE_ID_HINTS):
            score += 26
            rationale.append("Remote ID style Wi-Fi hint.")
        if event.get("feature_flags", {}).get("hidden_ssid") and event.get("feature_flags", {}).get("high_band"):
            score += 16
            rationale.append("Hidden high-band Wi-Fi activity retained.")
        if event.get("feature_flags", {}).get("controller_like"):
            score += 14
            rationale.append("Controller-like Wi-Fi relationship observed.")
        if recurrence >= 6:
            score += 12
            rationale.append("Repeated Wi-Fi recurrence in rolling window.")
        elif recurrence >= 3:
            score += 6
            rationale.append("Moderate Wi-Fi recurrence retained.")
        if rssi >= -68:
            score += 8
            rationale.append("Strong local Wi-Fi observation.")
        if any(token in ssid or token in vendor for token in self.INFRA_HINTS):
            score -= 10
            rationale.append("Infrastructure-like identity penalty applied after lead formation.")
        if str(event.get("ssid") or "") in set(baseline.get("common_ssids") or []):
            score -= 8
            rationale.append("Seen in baseline SSID set.")
        return {"anomaly_score": max(0, score), "rationale": rationale}

    def score_sdr(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        delta = float(event.get("anomaly_delta_db") or 0.0)
        band = str(event.get("band") or "unknown")
        profile = str(event.get("profile") or "")
        persistence = float(event.get("rolling_persistence") or 0.0)
        density = float((event.get("burst_metrics") or {}).get("density") or 0.0)
        recurrence = float((event.get("burst_metrics") or {}).get("recurrence") or 0.0)
        score = 0
        rationale: List[str] = []
        if delta >= 30:
            score += 24
            rationale.append("Strong SDR anomaly delta above local noise floor.")
        elif delta >= 20:
            score += 16
            rationale.append("Moderate SDR anomaly delta above local noise floor.")
        if band in {"2.4 GHz", "5.8 GHz"}:
            score += 8
            rationale.append("Observed in drone-relevant band.")
        if "drone_58" in profile or "drone_24" in profile:
            score += 8
            rationale.append("Drone-focused SDR profile retained the event.")
        if density >= 0.6:
            score += 10
            rationale.append("High burst density observed.")
        if recurrence >= 2.0:
            score += 8
            rationale.append("Burst recurrence observed.")
        if persistence >= 0.55:
            score += 10
            rationale.append("Cluster persistence retained across the rolling window.")
        return {"anomaly_score": max(0, score), "rationale": rationale}


class TemporalEvidenceAccumulator:
    def __init__(self, window_seconds: float = 5.0) -> None:
        self.window_seconds = window_seconds

    def summarize(self, events: List[Dict[str, Any]], now: float) -> Dict[str, Any]:
        recent = [event for event in events if float(event.get("timestamp") or 0.0) >= now - self.window_seconds]
        if not recent:
            return {"count": 0, "recurrence": 0, "last_seen": None, "density": 0.0}
        first = min(float(event.get("timestamp") or now) for event in recent)
        span = max(0.5, now - first)
        return {
            "count": len(recent),
            "recurrence": len(recent),
            "last_seen": max(float(event.get("timestamp") or 0.0) for event in recent),
            "density": min(1.0, len(recent) / span),
        }


class LeadPromotionManager:
    def promote(self, lead: Dict[str, Any]) -> Dict[str, Any]:
        sensors = set(lead.get("sensor_sources") or [])
        anomaly_score = float(lead.get("anomaly_score") or 0.0)
        recurrence = int(lead.get("temporal", {}).get("recurrence") or 0)
        decoder_evidence = bool(lead.get("decoder_evidence"))
        if decoder_evidence:
            state = "confirmed_drone_evidence"
        elif len(sensors) >= 2 and anomaly_score >= 60:
            state = "probable_drone"
        elif len(sensors) >= 2 or recurrence >= 3:
            state = "correlated_drone_candidate"
        elif anomaly_score >= 30:
            state = "weak_drone_candidate"
        elif "sdr" in sensors:
            state = "rf_anomaly"
        else:
            state = "wifi_anomaly"
        confidence = max(8, min(95, int(anomaly_score + recurrence * 5 + (10 if len(sensors) >= 2 else 0))))
        return {
            "current_state": state,
            "confidence": confidence,
            "operator_label": state.replace("_", " ").title(),
        }


class BandAttentionModel:
    def build(self, leads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pressure: Dict[str, float] = defaultdict(float)
        reasons: Dict[str, List[str]] = defaultdict(list)
        for lead in leads:
            band = str(lead.get("band_focus") or "unknown")
            value = float(lead.get("confidence") or 0.0) + float(lead.get("anomaly_score") or 0.0) / 2.0
            pressure[band] += value
            reasons[band].extend((lead.get("rationale") or [])[:2])
        rows = []
        for band, score in sorted(pressure.items(), key=lambda item: item[1], reverse=True):
            if band == "unknown":
                continue
            rows.append(
                {
                    "band": band,
                    "attention_score": round(score, 1),
                    "priority": "high" if score >= 120 else ("medium" if score >= 50 else "watch"),
                    "rationale": list(dict.fromkeys(reasons[band]))[:4],
                }
            )
        return rows[:4]


class AdaptiveScheduler:
    def decide(self, leads: Iterable[Dict[str, Any]], band_attention: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        top_band = band_attention[0]["band"] if band_attention else ""
        for lead in list(leads)[:6]:
            band = str(lead.get("band_focus") or top_band or "unknown")
            state = str(lead.get("current_state") or "")
            lead_id = str(lead.get("lead_id") or "")
            if state in {"rf_anomaly", "wifi_anomaly", "weak_drone_candidate"}:
                actions.append(
                    {
                        "timestamp": time.time(),
                        "lead_id": lead_id,
                        "action": "recheck_window",
                        "sensor": "wifi+sdr",
                        "band": band,
                        "reason": f"Weak lead retained in {band}; scheduling short recheck window.",
                    }
                )
            if "5.8" in band:
                actions.append(
                    {
                        "timestamp": time.time(),
                        "lead_id": lead_id,
                        "action": "increase_sdr_dwell",
                        "sensor": "sdr",
                        "band": band,
                        "reason": "5.8 GHz anomaly pressure elevated; dwell more aggressively in DJI-relevant band.",
                    }
                )
            elif "2.4" in band:
                actions.append(
                    {
                        "timestamp": time.time(),
                        "lead_id": lead_id,
                        "action": "prioritize_wifi_channels",
                        "sensor": "wifi",
                        "band": band,
                        "reason": "2.4 GHz anomaly pressure elevated; prioritize aligned Wi-Fi channels.",
                    }
                )
            if state in {"correlated_drone_candidate", "probable_drone", "confirmed_drone_evidence"}:
                actions.append(
                    {
                        "timestamp": time.time(),
                        "lead_id": lead_id,
                        "action": "confirmation_window",
                        "sensor": "wifi+sdr",
                        "band": band,
                        "reason": "Correlated lead observed; preserve evidence and hold confirmation window.",
                    }
                )
        deduped: List[Dict[str, Any]] = []
        seen: set[Tuple[str, str, str]] = set()
        for item in actions:
            key = (str(item.get("lead_id")), str(item.get("action")), str(item.get("band")))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:16]


class FusionStateStore:
    def __init__(self) -> None:
        self.events_by_key: Dict[str, List[Dict[str, Any]]] = {}
        self.leads: Dict[str, Dict[str, Any]] = {}

    def prune(self, now: float, horizon_seconds: float = 12.0) -> None:
        for key in list(self.events_by_key.keys()):
            kept = [event for event in self.events_by_key[key] if float(event.get("timestamp") or 0.0) >= now - horizon_seconds]
            if kept:
                self.events_by_key[key] = kept
            else:
                self.events_by_key.pop(key, None)
        for lead_id in list(self.leads.keys()):
            if float(self.leads[lead_id].get("last_seen") or 0.0) < now - horizon_seconds:
                self.leads.pop(lead_id, None)

    def append_events(self, grouped_events: Dict[str, List[Dict[str, Any]]]) -> None:
        for key, rows in grouped_events.items():
            self.events_by_key.setdefault(key, []).extend(rows)


@dataclass
class AssuranceSnapshot:
    leads: List[Dict[str, Any]]
    anomalies_wifi: List[Dict[str, Any]]
    anomalies_sdr: List[Dict[str, Any]]
    band_attention: List[Dict[str, Any]]
    scheduler_actions: List[Dict[str, Any]]
    fusion_windows: List[Dict[str, Any]]
    raw_filtered_counts: Dict[str, Any]
    sensor_sync: Dict[str, Any]


class DetectionAssuranceEngine:
    def __init__(self) -> None:
        self.normalizer = EvidenceNormalizer()
        self.anomaly_scoring = AnomalyScoringService()
        self.accumulator = TemporalEvidenceAccumulator()
        self.promotion = LeadPromotionManager()
        self.band_attention_model = BandAttentionModel()
        self.scheduler = AdaptiveScheduler()
        self.state = FusionStateStore()

    def evaluate(
        self,
        *,
        wifi_rows: Iterable[Dict[str, Any]],
        sdr_rows: Iterable[Dict[str, Any]],
        baseline: Dict[str, Any],
        scan_profile: str,
        now: float | None = None,
    ) -> AssuranceSnapshot:
        current_time = float(now or time.time())
        normalized_wifi = self.normalizer.normalize_wifi(wifi_rows)
        normalized_sdr = self.normalizer.normalize_sdr(sdr_rows)

        anomalies_wifi: List[Dict[str, Any]] = []
        anomalies_sdr: List[Dict[str, Any]] = []
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for event in normalized_wifi:
            scored = self.anomaly_scoring.score_wifi(event, baseline)
            record = {**event, **scored}
            anomalies_wifi.append(record)
            if record["anomaly_score"] >= 12:
                key = f"wifi:{event.get('band')}:{event.get('bssid') or event.get('ssid')}"
                grouped[key].append(record)

        for event in normalized_sdr:
            scored = self.anomaly_scoring.score_sdr(event, baseline)
            record = {**event, **scored}
            anomalies_sdr.append(record)
            if record["anomaly_score"] >= 14:
                key = f"sdr:{event.get('band')}:{event.get('cluster_id')}"
                grouped[key].append(record)

        band_windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for rows in grouped.values():
            for row in rows:
                band_windows[str(row.get("band") or "unknown")].append(row)
        if len(band_windows.get("5.8 GHz", [])) and len(band_windows.get("2.4 GHz", [])):
            fusion_key = "fused:dual-band"
            grouped[fusion_key].extend(band_windows["5.8 GHz"][:3])
            grouped[fusion_key].extend(band_windows["2.4 GHz"][:3])

        self.state.append_events(grouped)
        self.state.prune(current_time)

        leads: List[Dict[str, Any]] = []
        fusion_windows: List[Dict[str, Any]] = []
        for key, events in sorted(self.state.events_by_key.items()):
            temporal = self.accumulator.summarize(events, current_time)
            if not temporal["count"]:
                continue
            sensor_sources = sorted({str(event.get("kind") or "") for event in events})
            band_focus = next((str(event.get("band") or "") for event in events if event.get("band")), "unknown")
            anomaly_score = max(float(event.get("anomaly_score") or 0.0) for event in events)
            decoder_evidence = any("remote id" in " ".join(event.get("rationale") or []).lower() for event in events)
            rationale = list(dict.fromkeys(sum([list(event.get("rationale") or []) for event in events], [])))[:6]
            lead_id = hashlib.sha1(f"{key}|{band_focus}".encode("utf-8")).hexdigest()[:14]
            lead = {
                "lead_id": lead_id,
                "created_at": min(float(event.get("timestamp") or current_time) for event in events),
                "last_seen": temporal["last_seen"] or current_time,
                "lead_type": "fused" if len(sensor_sources) >= 2 else sensor_sources[0],
                "anomaly_score": anomaly_score,
                "band_focus": band_focus,
                "sensor_sources": sensor_sources,
                "temporal": temporal,
                "decoder_evidence": decoder_evidence,
                "related_wifi_events": [event["event_id"] for event in events if event.get("kind") == "wifi"][:24],
                "related_sdr_events": [event["event_id"] for event in events if event.get("kind") == "sdr"][:24],
                "rationale": rationale,
                "evidence_paths": sorted({str(event.get("raw_evidence_pointer") or "") for event in events if event.get("raw_evidence_pointer")}),
                "scheduler_hints": [],
                "score_breakdown": {
                    "anomaly_score": anomaly_score,
                    "temporal_density": temporal["density"],
                    "recurrence": temporal["recurrence"],
                    "sensor_count": len(sensor_sources),
                },
            }
            lead.update(self.promotion.promote(lead))
            self.state.leads[lead_id] = dict(lead)
            leads.append(lead)
            fusion_windows.append(
                {
                    "lead_id": lead_id,
                    "window_started_at": lead["created_at"],
                    "last_seen": lead["last_seen"],
                    "band_focus": band_focus,
                    "sensor_sources": sensor_sources,
                    "recurrence": temporal["recurrence"],
                    "density": temporal["density"],
                }
            )

        leads.sort(key=lambda item: (int(item.get("confidence") or 0), float(item.get("anomaly_score") or 0.0)), reverse=True)
        band_attention = self.band_attention_model.build(leads)
        scheduler_actions = self.scheduler.decide(leads, band_attention)
        hints_by_lead: Dict[str, List[str]] = defaultdict(list)
        for item in scheduler_actions:
            hints_by_lead[str(item.get("lead_id") or "")].append(str(item.get("action") or ""))
        for lead in leads:
            lead["scheduler_hints"] = hints_by_lead.get(str(lead.get("lead_id") or ""), [])[:4]

        sync_status = "idle"
        if any("wifi" in (lead.get("sensor_sources") or []) and "sdr" in (lead.get("sensor_sources") or []) for lead in leads):
            sync_status = "correlated"
        elif leads:
            sync_status = "tracking"
        sensor_sync = {
            "status": sync_status,
            "scan_profile": scan_profile,
            "correlated_lead_count": len([lead for lead in leads if len(lead.get("sensor_sources") or []) >= 2]),
            "wifi_only_lead_count": len([lead for lead in leads if lead.get("sensor_sources") == ["wifi"]]),
            "sdr_only_lead_count": len([lead for lead in leads if lead.get("sensor_sources") == ["sdr"]]),
        }
        raw_filtered_counts = {
            "raw_wifi_events": len(normalized_wifi),
            "raw_sdr_events": len(normalized_sdr),
            "wifi_anomalies": len(anomalies_wifi),
            "sdr_anomalies": len(anomalies_sdr),
            "active_leads": len(leads),
        }
        return AssuranceSnapshot(
            leads=leads[:24],
            anomalies_wifi=anomalies_wifi[:120],
            anomalies_sdr=anomalies_sdr[:120],
            band_attention=band_attention,
            scheduler_actions=scheduler_actions,
            fusion_windows=fusion_windows[:48],
            raw_filtered_counts=raw_filtered_counts,
            sensor_sync=sensor_sync,
        )
