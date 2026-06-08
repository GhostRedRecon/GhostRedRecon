# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/ble/ble_decoder_worker.py
# VERSION:      v6.2.0 (TRUSTED IDENTITIES + SCAN RESPONSE PAIRING)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations

import threading
import time
import logging
import os
import hashlib
import json
from collections import deque
from typing import Dict, Any, Optional, List
from pathlib import Path

from backend.intel.ble.ble_gr_flowgraph import BLEFlowgraph
from backend.intel.ble.ble_knowledge_base import BLEKnowledgeBase
from backend.intel.ble.decoder_backends import get_decoder_backends, preferred_backend_id
from backend.intel.ble.ble_packet_parser import BLEPacketParser
from backend.intel.ble.device_tracker import BLEDeviceTracker
from backend.config.project_config import get_project_config

try:
    from backend.intel.identity.identity_intelligence import IdentityIntelligence
except Exception:
    IdentityIntelligence = None

try:
    from backend.intel.ble.ble_channel_correlator import BLEChannelCorrelator
except Exception:
    BLEChannelCorrelator = None

try:
    from backend.intel.behavior.behavior_profiler import BehaviorProfiler
except Exception:
    BehaviorProfiler = None

try:
    from backend.intel.identity.cross_session_identity_engine import CrossSessionIdentityEngine
except Exception:
    CrossSessionIdentityEngine = None

try:
    from backend.intel.identity.ble_fingerprinting_engine import BLEFingerprintingEngine
except Exception:
    BLEFingerprintingEngine = None

try:
    from backend.intel.targeting.targeting_engine import TargetingEngine
except Exception:
    TargetingEngine = None

try:
    from backend.intel.alerts.alert_engine import AlertEngine
except Exception:
    AlertEngine = None

log = logging.getLogger("ghostrecon.ble_decoder")


class BLEDecoderWorker:

    VERSION = "6.2.0"

    BLE_CHANNELS = [2402e6, 2426e6, 2480e6]

    BASE_CAPTURE_TIME_SEC = 0.2
    ACTIVE_CAPTURE_TIME_SEC = 0.6
    MAX_CAPTURE_TIME_SEC = 1.0
    LOOP_DELAY_SEC = 0.1

    DEDUP_WINDOW_SEC = 1.0
    MAX_EVENT_HISTORY = 512
    TRUSTED_EVIDENCE_SCORE = 0.52
    TRUSTED_CONFIDENCE = 0.58
    SCAN_RESPONSE_WINDOW_SEC = 2.0
    RELAXED_SCAN_RESPONSE_WINDOW_SEC = 0.9
    DEFAULT_SWEEP_DWELL_MS = 2500
    MIN_SWEEP_DWELL_MS = 1500
    MAX_SWEEP_DWELL_MS = 6000
    VENDOR_FOCUS_EVENT_THRESHOLD = 4
    BLE_EXPORT_MAX_RECORDS = 4000

    def __init__(self, oui_path: str = "backend/config/oui/oui_full.txt"):

        self.oui_db = self._load_oui(oui_path)
        config = get_project_config().get("sdr", {})
        runtime_config = config.get("runtime", {})
        ble_profile_config = config.get("bleProfiles", {})
        self.iq_path = runtime_config.get("iqPath", "/dev/shm/ghostrecon_iq.iq")
        self.sample_rate = int(runtime_config.get("sampleRate", 10_000_000))
        self.runtime = None
        self.capture_profiles = self._load_capture_profiles(ble_profile_config)
        self.default_profile_id = ble_profile_config.get("defaultProfile", "balanced")
        if self.default_profile_id not in self.capture_profiles:
            self.default_profile_id = "balanced"
        self.active_profile_id = self.default_profile_id
        self.active_profile_reason = "config_default"
        project_root = Path(__file__).resolve().parents[3]
        self.packet_export_path = project_root / "rf_reports" / "ble_decoder_packets.jsonl"
        self.packet_export_count = 0

        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.backend_id: Optional[str] = None
        self.last_error: Optional[str] = None
        self.decoded_event_count = 0
        self.last_capture_at: Optional[float] = None
        self.last_event_at: Optional[float] = None
        self.capture_count = 0
        self.packet_count = 0
        self.empty_capture_count = 0
        self.low_evidence_event_count = 0

        self._buffer: List[Dict[str, Any]] = []
        self._history = deque(maxlen=self.MAX_EVENT_HISTORY)
        self._recent_advertisers = deque(maxlen=96)
        self._lock = threading.Lock()
        self.channel_activity: Dict[float, Dict[str, float]] = {
            float(freq): {"score": 0.0, "last_hit_at": 0.0}
            for freq in self.BLE_CHANNELS
        }

        self.parser = BLEPacketParser()
        self.knowledge_base = BLEKnowledgeBase()
        self.device_cache: Dict[str, Dict[str, Any]] = {}
        self.tracker = BLEDeviceTracker()

        # ENGINES
        self.identity = IdentityIntelligence() if IdentityIntelligence else None
        self.correlator = BLEChannelCorrelator() if BLEChannelCorrelator else None
        self.behavior = BehaviorProfiler() if BehaviorProfiler else None
        self.cross_identity = CrossSessionIdentityEngine() if CrossSessionIdentityEngine else None
        self.fingerprinting = BLEFingerprintingEngine() if BLEFingerprintingEngine else None
        self.targeting = TargetingEngine() if TargetingEngine else None
        self.alerts = AlertEngine() if AlertEngine else None

        log.info(
            "[BLE] Decoder initialized | Version=%s | OUI=%d",
            self.VERSION,
            len(self.oui_db),
        )

    def bind_runtime(self, runtime: Any) -> None:
        self.runtime = runtime
        try:
            sdr = getattr(runtime, "sdr", None)
            if sdr is not None:
                self.iq_path = getattr(sdr, "iq_path", self.iq_path) or self.iq_path
                self.sample_rate = int(getattr(sdr, "sample_rate", self.sample_rate) or self.sample_rate)
        except Exception:
            pass

    # =========================================================================
    def start(self):
        if self.running:
            return

        self.backend_id = preferred_backend_id()
        self.last_error = None
        if not self.backend_id:
            self.last_error = "No BLE decode backend is available. Install GNU Radio/osmosdr or btle_rx."
            log.warning("[BLE] %s", self.last_error)
            return
        if self.backend_id != "gnuradio_hackrf":
            self.last_error = (
                f"BLE backend {self.backend_id} is available but not yet bridged in-process. "
                "Set GHOSTRECON_BLE_BACKEND=gnuradio_hackrf for the integrated HackRF path."
            )
            log.warning("[BLE] %s", self.last_error)
            return

        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

        log.info("[BLE] Decoder started | backend=%s", self.backend_id)

    def stop(self):
        self.running = False

        if self.thread:
            self.thread.join(timeout=2)

        log.info("[BLE] Decoder stopped")

    def clear_runtime_state(self) -> None:
        with self._lock:
            self._buffer.clear()
            self._history.clear()
            self._recent_advertisers.clear()
            self.device_cache.clear()
            self.packet_export_count = 0
            self.decoded_event_count = 0
            self.last_capture_at = None
            self.last_event_at = None
            self.capture_count = 0
            self.packet_count = 0
            self.empty_capture_count = 0
            self.low_evidence_event_count = 0
            self.channel_activity = {
                float(freq): {"score": 0.0, "last_hit_at": 0.0}
                for freq in self.BLE_CHANNELS
            }
        try:
            if self.packet_export_path.exists():
                self.packet_export_path.unlink()
        except Exception as exc:
            log.debug("[BLE] packet export clear failed: %s", exc)
        log.info("[BLE] Decoder runtime state cleared")

    def get_events(self) -> List[Dict[str, Any]]:
        with self._lock:
            data = self._buffer[:]
            self._buffer.clear()
        return data

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            if limit <= 0:
                return []
            return [dict(event) for event in list(self._history)[-limit:]]

    def get_device_snapshot(self, limit: int = 100, trusted_only: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            devices = []
            for mac, meta in sorted(
                self.device_cache.items(),
                key=lambda item: (
                    item[1].get("trust_score", 0.0),
                    item[1].get("best_evidence_score", 0.0),
                    item[1].get("seen_count", 0),
                    item[1].get("last_seen", 0.0),
                ),
                reverse=True,
            ):
                if trusted_only and not bool(meta.get("trusted_identity")):
                    continue
                devices.append(
                    {
                        "mac_address": mac,
                        "vendor": meta.get("vendor"),
                        "vendor_source": meta.get("vendor_source"),
                        "vendor_confidence": meta.get("vendor_confidence"),
                        "device_name": meta.get("device_name"),
                        "device_hint": meta.get("device_hint"),
                        "manufacturer_id": meta.get("manufacturer_id"),
                        "manufacturer_company": meta.get("manufacturer_company"),
                        "manufacturer_confirmed": bool(meta.get("manufacturer_confirmed")),
                        "service_uuids": list(meta.get("service_uuids") or []),
                        "service_uuid_names": list(meta.get("service_uuid_names") or []),
                        "service_data_keys": sorted(list(meta.get("service_data_keys") or [])),
                        "appearance": meta.get("appearance"),
                        "appearance_label": meta.get("appearance_label"),
                        "tx_power": meta.get("tx_power"),
                        "privacy_state": meta.get("privacy_state"),
                        "address_rotation_count": meta.get("address_rotation_count", 0),
                        "observed_pdu_types": sorted(list(meta.get("observed_pdu_types") or [])),
                        "extended_advertising_seen": bool(meta.get("extended_advertising_seen")),
                        "probable_vendor_family": meta.get("probable_vendor_family"),
                        "probable_product_family": meta.get("probable_product_family"),
                        "tracker_like": bool(meta.get("tracker_like")),
                        "beacon_like": bool(meta.get("beacon_like")),
                        "apple_findmy_like": bool(meta.get("apple_findmy_like")),
                        "payload_signature": meta.get("payload_signature"),
                        "backend": meta.get("backend"),
                        "best_confidence": meta.get("best_confidence"),
                        "best_evidence_score": meta.get("best_evidence_score"),
                        "trust_score": meta.get("trust_score"),
                        "latest_evidence_score": meta.get("latest_evidence_score"),
                        "evidence_quality": meta.get("evidence_quality"),
                        "evidence_reasons": list(meta.get("evidence_reasons") or []),
                        "trusted_identity": bool(meta.get("trusted_identity")),
                        "trust_reasons": list(meta.get("trust_reasons") or []),
                        "paired_scan_response": bool(meta.get("paired_scan_response")),
                        "paired_scan_response_count": int(meta.get("paired_scan_response_count") or 0),
                        "ad_structure_count": meta.get("ad_structure_count", 0),
                        "manufacturer_data_present": bool(meta.get("manufacturer_data_present")),
                        "service_hint_count": meta.get("service_hint_count", 0),
                        "scan_response_seen_count": meta.get("scan_response_seen_count", 0),
                        "crc_valid_count": meta.get("crc_valid_count", 0),
                        "channels": sorted(list(meta.get("channels") or [])),
                        "first_seen": meta.get("first_seen"),
                        "last_seen": meta.get("last_seen"),
                        "seen_count": meta.get("seen_count", 0),
                        "last_frequency_mhz": meta.get("last_frequency_mhz"),
                        "last_rssi": meta.get("last_rssi"),
                        "spam_like": bool(meta.get("spam_like")),
                        "spam_confidence": meta.get("spam_confidence", 0.0),
                        "spam_reasons": list(meta.get("spam_reasons") or []),
                    }
                )
                if len(devices) >= max(limit, 0):
                    break
            return devices

    def get_status(self) -> Dict[str, Any]:
        backends = get_decoder_backends()
        recommended_profile = self.recommend_capture_profile()
        dwell_recommendations = self.recommend_channel_dwell()
        return {
            "running": self.running,
            "backend_id": self.backend_id,
            "backend_label": next((backend["label"] for backend in backends if backend["backend_id"] == self.backend_id), None),
            "decoded_event_count": self.decoded_event_count,
            "cached_device_count": len(self.device_cache),
            "trusted_identity_count": len([meta for meta in self.device_cache.values() if meta.get("trusted_identity")]),
            "capture_count": self.capture_count,
            "packet_count": self.packet_count,
            "empty_capture_count": self.empty_capture_count,
            "low_evidence_event_count": self.low_evidence_event_count,
            "last_capture_at": self.last_capture_at,
            "last_event_at": self.last_event_at,
            "channel_activity": {
                str(int(freq / 1e6)): {
                    "score": round(float(stats.get("score") or 0.0), 2),
                    "last_hit_at": stats.get("last_hit_at") or 0.0,
                }
                for freq, stats in self.channel_activity.items()
            },
            "channel_dwell_ms": dwell_recommendations,
            "active_capture_profile": self.capture_profiles.get(self.active_profile_id, {}),
            "recommended_capture_profile": recommended_profile,
            "packet_export_path": str(self.packet_export_path),
            "packet_export_count": self.packet_export_count,
            "available_backends": backends,
            "last_error": self.last_error,
        }

    # =========================================================================
    def _run(self):

        while self.running:
            capture_plan = self._capture_frequencies()
            if not capture_plan:
                time.sleep(self.LOOP_DELAY_SEC)
                continue
            for freq in capture_plan:

                if not self.running:
                    break

                try:
                    self._capture_channel(freq)
                except Exception as e:
                    self.last_error = str(e)
                    log.debug("[BLE] Capture error @ %.1f MHz: %s", freq / 1e6, e)

                time.sleep(self.LOOP_DELAY_SEC)

    # =========================================================================
    def _runtime_state(self) -> Dict[str, Any]:
        runtime = self.runtime
        if runtime is None:
            return {}
        try:
            sdr = getattr(runtime, "sdr", None)
            if sdr is None or not hasattr(sdr, "get_state"):
                return {}
            return sdr.get_state() or {}
        except Exception:
            return {}

    def _capture_frequencies(self) -> List[float]:
        state = self._runtime_state()
        freq_mhz = state.get("freq_mhz")
        running = bool(state.get("running"))
        if running and freq_mhz is not None:
            try:
                freq_hz = float(freq_mhz) * 1e6
            except Exception:
                freq_hz = None
            if freq_hz and 2400e6 <= freq_hz <= 2485e6:
                return [freq_hz]
            return []
        return list(self.BLE_CHANNELS)

    def _load_capture_profiles(self, profile_config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        profiles = {}
        for profile in profile_config.get("profiles", []):
            profile_id = str(profile.get("id") or "").strip()
            if not profile_id:
                continue
            profiles[profile_id] = {
                "id": profile_id,
                "label": profile.get("label") or profile_id.replace("_", " ").title(),
                "sample_rate": int(profile.get("sampleRate", self.sample_rate)),
                "amp_enable": bool(profile.get("ampEnable", False)),
                "lna_gain": int(profile.get("lnaGain", 24)),
                "vga_gain": int(profile.get("vgaGain", 32)),
                "iq_snapshot_seconds": float(profile.get("iqSnapshotSeconds", 0.12)),
                "flowgraph_capture_seconds": float(profile.get("flowgraphCaptureSeconds", 0.22)),
            }
        if "balanced" not in profiles:
            profiles["balanced"] = {
                "id": "balanced",
                "label": "Balanced BLE",
                "sample_rate": self.sample_rate,
                "amp_enable": False,
                "lna_gain": 24,
                "vga_gain": 32,
                "iq_snapshot_seconds": 0.12,
                "flowgraph_capture_seconds": 0.22,
            }
        return profiles

    def recommend_capture_profile(self, freq_mhz: Optional[float] = None) -> Dict[str, Any]:
        capture_count = max(1, int(self.capture_count or 0))
        packet_ratio = float(self.packet_count or 0) / float(capture_count)
        empty_ratio = float(self.empty_capture_count or 0) / float(capture_count)
        low_ratio = float(self.low_evidence_event_count or 0) / float(max(1, self.decoded_event_count or 0))
        profile_id = self.default_profile_id
        reason = "default_balanced"

        if self.decoded_event_count == 0 and self.packet_count == 0 and self.empty_capture_count >= 3:
            profile_id = "high_sensitivity"
            reason = "no_packets_high_empty_ratio"
        elif packet_ratio < 0.08 and empty_ratio > 0.65:
            profile_id = "high_sensitivity"
            reason = "weak_decode_rate"
        elif self.packet_count >= self.VENDOR_FOCUS_EVENT_THRESHOLD and low_ratio > 0.72:
            profile_id = "vendor_focus" if "vendor_focus" in self.capture_profiles else "low_noise"
            reason = "payload_recovery_focus"
        elif self.packet_count > 0 and low_ratio > 0.8:
            profile_id = "low_noise"
            reason = "many_low_confidence_packets"
        elif packet_ratio > 0.22 and low_ratio < 0.45:
            profile_id = "balanced"
            reason = "stable_decode_rate"

        profile = dict(self.capture_profiles.get(profile_id, self.capture_profiles[self.default_profile_id]))
        profile["reason"] = reason
        if freq_mhz is not None:
            profile["freq_mhz"] = float(freq_mhz)
        self.active_profile_id = profile["id"]
        self.active_profile_reason = reason
        return profile

    def _runtime_iq_snapshot_path(self, freq: float) -> Optional[str]:
        state = self._runtime_state()
        if not state.get("running"):
            return None
        iq_path = self.iq_path
        if not iq_path or not os.path.exists(iq_path):
            return None
        raw_size = os.path.getsize(iq_path)
        if raw_size < 4096:
            return None
        profile = self.recommend_capture_profile(freq / 1e6)
        capture_seconds = min(
            0.45,
            max(float(profile.get("iq_snapshot_seconds", 0.12)), self._capture_duration_for_freq(freq)),
        )
        sample_rate = max(1, int(self.sample_rate))
        target_bytes = int(sample_rate * capture_seconds * 2)
        read_size = max(4096, min(raw_size, target_bytes))
        if read_size % 2:
            read_size -= 1
        if read_size <= 0:
            return None

        snapshot_path = f"/tmp/ghostrecon_ble_{int(freq)}.iq"
        try:
            with open(iq_path, "rb") as src:
                src.seek(-read_size, os.SEEK_END)
                data = src.read(read_size)
            if len(data) < 4096:
                return None
            Path(snapshot_path).write_bytes(data)
            return snapshot_path
        except Exception:
            return None

    # =========================================================================
    def _inject_gain(self, flow):

        try:
            if hasattr(flow, "source"):
                src = flow.source

                try:
                    src.set_gain(40)
                except Exception:
                    pass

                try:
                    src.set_if_gain(20)
                except Exception:
                    pass

                try:
                    src.set_bb_gain(20)
                except Exception:
                    pass

        except Exception as e:
            log.debug("[BLE] Gain injection failed: %s", e)

    # =========================================================================
    def _safe_pipeline_stage(self, name, engine, data):

        if not engine:
            print(f"[PIPELINE] {name}: SKIPPED")
            return data

        try:
            out = engine.process(data)

            if not isinstance(out, list):
                print(f"[PIPELINE] {name}: INVALID RETURN → keeping original")
                return data

            print(f"[PIPELINE] {name}: {len(data)} → {len(out)}")

            if len(out) == 0 and len(data) > 0:
                print(f"[PIPELINE] ⚠️ {name} DROPPED ALL EVENTS → RECOVERING")
                return data

            return out

        except Exception as e:
            print(f"[PIPELINE] ❌ {name} ERROR: {e}")
            return data

    # =========================================================================
    def _capture_duration_for_freq(self, freq: float) -> float:
        stats = self.channel_activity.get(float(freq), {})
        score = float(stats.get("score") or 0.0)
        if score >= 2.5:
            return self.MAX_CAPTURE_TIME_SEC
        if score >= 1.0:
            return self.ACTIVE_CAPTURE_TIME_SEC
        return self.BASE_CAPTURE_TIME_SEC

    def _update_channel_activity(self, freq: float, hit_count: int) -> None:
        stats = self.channel_activity.setdefault(float(freq), {"score": 0.0, "last_hit_at": 0.0})
        score = float(stats.get("score") or 0.0) * 0.75
        if hit_count > 0:
            score = min(4.0, score + (0.7 * hit_count))
            stats["last_hit_at"] = time.time()
        stats["score"] = score

    def _compute_trust_score(self, meta: Dict[str, Any]) -> float:
        score = 0.0
        score += min(0.22, float(meta.get("best_evidence_score") or 0.0) * 0.3)
        score += min(0.14, float(meta.get("best_confidence") or 0.0) * 0.14)
        score += min(0.15, int(meta.get("seen_count") or 0) * 0.025)
        score += min(0.18, int(meta.get("crc_valid_count") or 0) * 0.09)
        score += min(0.1, int(meta.get("scan_response_seen_count") or 0) * 0.05)
        score += min(0.06, len(list(meta.get("service_uuid_names") or [])) * 0.02)
        if meta.get("manufacturer_id"):
            score += 0.04
        if meta.get("device_name"):
            score += 0.08
        if meta.get("manufacturer_confirmed"):
            score += 0.18
        elif meta.get("manufacturer_company"):
            score += 0.04
        if meta.get("vendor_source") in {"manufacturer_company", "signature_match"}:
            score += 0.08
        if meta.get("paired_scan_response"):
            score += 0.12
        if meta.get("service_data_keys"):
            score += min(0.08, len(list(meta.get("service_data_keys") or [])) * 0.04)
        if meta.get("trusted_identity"):
            score += 0.12
        if meta.get("privacy_state") == "randomized":
            score -= 0.05
        return round(max(0.0, min(score, 1.0)), 3)

    def _assess_spam_behavior(self, meta: Dict[str, Any]) -> tuple[bool, float, List[str]]:
        reasons: List[str] = []
        score = 0.0
        seen_count = int(meta.get("seen_count") or 0)
        crc_valid_count = int(meta.get("crc_valid_count") or 0)
        scan_response_seen_count = int(meta.get("scan_response_seen_count") or 0)
        address_rotation_count = int(meta.get("address_rotation_count") or 0)
        service_hint_count = int(meta.get("service_hint_count") or 0)
        paired_scan_response = bool(meta.get("paired_scan_response"))
        observed_pdu_types = {
            str(label or "").upper()
            for label in (meta.get("observed_pdu_types") or [])
            if label
        }
        best_evidence_score = float(meta.get("best_evidence_score") or 0.0)
        no_identity_payload = (
            not meta.get("manufacturer_confirmed")
            and not meta.get("manufacturer_data_present")
            and service_hint_count == 0
            and not meta.get("service_data_keys")
            and not meta.get("device_name")
        )

        # Weak single-hit packets are uncertainty, not operator-safe spam evidence.
        if (
            seen_count < 3
            and address_rotation_count < 2
            and scan_response_seen_count == 0
            and not paired_scan_response
            and crc_valid_count == 0
            and best_evidence_score < 0.18
        ):
            if meta.get("privacy_state") == "randomized":
                reasons.append("randomized_low_confidence")
                return False, 0.24, reasons
            return False, 0.12, ["low_confidence_rf_only"]

        if meta.get("privacy_state") == "randomized":
            score += 0.12
            reasons.append("randomized_address")
        if no_identity_payload and seen_count >= 3:
            score += 0.1
            reasons.append("no_manufacturer_identity")
        if service_hint_count == 0 and not meta.get("service_data_keys") and seen_count >= 3:
            score += 0.08
            reasons.append("low_payload_richness")
        if crc_valid_count == 0 and seen_count >= 4:
            score += 0.05
            reasons.append("no_crc_valid_packets")
        if best_evidence_score < 0.28 and seen_count >= 4:
            score += 0.05
            reasons.append("weak_identity_evidence")
        if seen_count >= 3:
            score += 0.16
            reasons.append("repeat_advertiser")
        if seen_count >= 5:
            score += 0.08
            reasons.append("high_repeat_density")
        if scan_response_seen_count >= 2 or paired_scan_response:
            score += 0.12
            reasons.append("scan_response_activity")
        if {"ADV_IND", "ADV_SCAN_IND", "SCAN_RSP"} & observed_pdu_types and len(observed_pdu_types) >= 2:
            score += 0.08
            reasons.append("multi_pdu_pattern")
        if address_rotation_count >= 2:
            score += 0.28
            reasons.append("address_churn")
        if address_rotation_count >= 4:
            score += 0.08
            reasons.append("high_address_churn")
        spam_confidence = round(max(0.0, min(score, 1.0)), 3)
        return spam_confidence >= 0.6, spam_confidence, reasons

    def _resolve_vendor_evidence(
        self,
        mac: str,
        parsed: Dict[str, Any],
        heuristics: Dict[str, Any],
        cached: Optional[Dict[str, Any]] = None,
    ) -> tuple[Optional[str], Optional[str], float]:
        manufacturer_company = parsed.get("manufacturer_company")
        probable_vendor_family = heuristics.get("probable_vendor_family")
        signature_match = heuristics.get("signature_match") or parsed.get("signature_match")
        privacy_state = self._privacy_state(parsed, mac)
        manufacturer_confirmed = self._is_confirmed_manufacturer(parsed, cached)

        if manufacturer_company and manufacturer_confirmed:
            return manufacturer_company, "manufacturer_company", 0.9
        if signature_match and signature_match.get("vendor"):
            return signature_match.get("vendor"), "signature_match", float(signature_match.get("confidence") or 0.78)
        if probable_vendor_family:
            return probable_vendor_family, "probable_vendor_family", 0.72
        if privacy_state == "public":
            oui_vendor = self._resolve_vendor(mac)
            if oui_vendor:
                return oui_vendor, "public_oui", 0.6
        return None, None, 0.0

    def recommend_channel_dwell(self, default_dwell_ms: int | None = None) -> Dict[str, int]:
        base = int(default_dwell_ms or self.DEFAULT_SWEEP_DWELL_MS)
        weights: Dict[float, float] = {}
        for freq in self.BLE_CHANNELS:
            stats = self.channel_activity.get(float(freq), {})
            activity_weight = 1.0 + min(3.0, float(stats.get("score") or 0.0) / 1.4)
            freshness_bonus = 0.0
            last_hit_at = float(stats.get("last_hit_at") or 0.0)
            if last_hit_at and (time.time() - last_hit_at) <= 20.0:
                freshness_bonus = 0.35
            weights[float(freq)] = activity_weight + freshness_bonus
        total_weight = sum(weights.values()) or float(len(self.BLE_CHANNELS))
        budget_ms = base * len(self.BLE_CHANNELS)
        recommendations: Dict[str, int] = {}
        for freq in self.BLE_CHANNELS:
            dwell = int(round(budget_ms * (weights[float(freq)] / total_weight)))
            recommendations[str(int(freq / 1e6))] = max(self.MIN_SWEEP_DWELL_MS, min(self.MAX_SWEEP_DWELL_MS, dwell))
        return recommendations

    # =========================================================================
    def _capture_channel(self, freq: float):
        if self.backend_id != "gnuradio_hackrf":
            raise RuntimeError(f"BLE backend {self.backend_id} is not implemented in-process yet")

        profile = self.recommend_capture_profile(freq / 1e6)
        iq_snapshot_path = self._runtime_iq_snapshot_path(freq)
        try:
            flow = BLEFlowgraph(freq=freq, samp_rate=self.sample_rate, iq_path=iq_snapshot_path)

            if not iq_snapshot_path:
                self._inject_gain(flow)

            flow.start()
            if iq_snapshot_path:
                time.sleep(
                    min(
                        0.5,
                        max(
                            float(profile.get("flowgraph_capture_seconds", 0.22)),
                            self._capture_duration_for_freq(freq),
                        ),
                    )
                )
            else:
                time.sleep(self._capture_duration_for_freq(freq))

            try:
                flow.stop()
            except Exception:
                pass

        except Exception as e:
            log.debug("[BLE] Flowgraph error: %s", e)
            return
        finally:
            if iq_snapshot_path:
                try:
                    os.unlink(iq_snapshot_path)
                except Exception:
                    pass

        self.capture_count += 1
        self.last_capture_at = time.time()

        try:
            bits = flow.get_data()
        except Exception:
            print("[DEBUG] Failed to get data from flowgraph")
            return

        if not bits:
            print("[DEBUG] No bits received from flowgraph")
            self.empty_capture_count += 1
            return

        try:
            bit_len = len(bits)
        except Exception:
            print("[DEBUG] Bits object invalid")
            return

        print(f"[DEBUG] Bitstream length: {bit_len}")
        print(f"[DEBUG] First 64 bits: {bits[:64]}")

        parsed_list = self.parser.parse(bits, freq=freq)
        self._update_channel_activity(freq, len(parsed_list))

        if not parsed_list:
            print("[DEBUG] No packets parsed → access address not found")
            self.empty_capture_count += 1
            return

        print(f"[DEBUG] Packets detected: {len(parsed_list)}")
        self.packet_count += len(parsed_list)

        now = time.time()
        channel = self._freq_to_channel(freq)

        events_batch = []

        for parsed in parsed_list:

            print(f"[DEBUG] Raw parsed packet: {parsed}")

            mac = self._normalize_mac(parsed.get("mac_address"))

            if not mac:
                print("[DEBUG] Packet missing MAC")
                continue

            cached = self.device_cache.get(mac)

            if not self._accept_packet(parsed, cached):
                print("[DEBUG] Packet rejected by BLE quality gate")
                continue

            print(f"[BLE] MAC detected: {mac}")

            if cached:
                cached["last_seen"] = now
                cached["seen_count"] += 1
            else:
                self.device_cache[mac] = {
                    "first_seen": now,
                    "last_seen": now,
                    "seen_count": 1,
                }
                cached = self.device_cache[mac]

            adv_data = parsed.get("adv_data") or {}
            if cached:
                adv_data = self._merge_adv_data(
                    {
                        "device_name": cached.get("device_name"),
                        "manufacturer_id": cached.get("manufacturer_id"),
                        "manufacturer_company": cached.get("manufacturer_company"),
                        "manufacturer_data": cached.get("manufacturer_data"),
                        "service_uuids": list(cached.get("service_uuids") or []),
                        "service_uuid_names": list(cached.get("service_uuid_names") or []),
                        "service_data": dict(cached.get("service_data") or {}),
                        "appearance": cached.get("appearance"),
                        "appearance_label": cached.get("appearance_label"),
                        "flags": None,
                        "tx_power": cached.get("tx_power"),
                        "ad_structure_count": cached.get("ad_structure_count") or 0,
                    },
                    adv_data,
                )
                parsed = self._merge_parsed_packet(parsed, {"adv_data": adv_data})
            rssi = parsed.get("rssi") or adv_data.get("rssi")
            heuristics = self._classify_ble_event(parsed, adv_data)
            payload_signature = self._payload_signature(parsed, adv_data)
            evidence_score, evidence_quality, evidence_reasons = self._compute_evidence_score(parsed, adv_data)
            confidence = self._compute_confidence(parsed, adv_data, rssi, evidence_score)
            paired_scan_response = self._pair_scan_response(
                mac=mac,
                parsed=parsed,
                channel=channel,
                timestamp=now,
                payload_signature=payload_signature,
            )

            if paired_scan_response:
                adv_data = self._merge_adv_data(
                    (paired_scan_response.get("adv_data") or {}),
                    adv_data,
                )
                parsed = self._merge_parsed_packet(parsed, paired_scan_response)
                heuristics = self._classify_ble_event(parsed, adv_data)
                payload_signature = self._payload_signature(parsed, adv_data)
                evidence_score, evidence_quality, evidence_reasons = self._compute_evidence_score(parsed, adv_data)
                confidence = self._compute_confidence(parsed, adv_data, rssi, evidence_score)

            manufacturer_confirmed = self._is_confirmed_manufacturer(parsed, cached)
            if not manufacturer_confirmed:
                parsed = dict(parsed)
                parsed["manufacturer_company"] = None

            vendor, vendor_source, vendor_confidence = self._resolve_vendor_evidence(mac, parsed, heuristics, cached)

            event = {
                "mac_address": mac,
                "vendor": vendor,
                "vendor_source": vendor_source,
                "vendor_confidence": vendor_confidence,
                "timestamp": now,
                "protocol": "BLE",
                "decoder_backend": self.backend_id,
                "channel": channel,
                "frequency": freq / 1e6,
                "confidence": confidence,
                "evidence_score": evidence_score,
                "evidence_quality": evidence_quality,
                "evidence_reasons": evidence_reasons,
                "crc_valid": bool(parsed.get("crc_valid")),
                "crc": parsed.get("crc"),
                "computed_crc": parsed.get("computed_crc"),
                "device_name": parsed.get("device_name"),
                "manufacturer_id": parsed.get("manufacturer_id"),
                "manufacturer_company": parsed.get("manufacturer_company"),
                "manufacturer_data": parsed.get("manufacturer_data"),
                "manufacturer_confirmed": manufacturer_confirmed,
                "service_uuids": parsed.get("service_uuids") or [],
                "service_uuid_names": parsed.get("service_uuid_names") or [],
                "service_data": parsed.get("service_data") or {},
                "service_data_keys": sorted(list((parsed.get("service_data") or {}).keys())),
                "appearance": parsed.get("appearance"),
                "appearance_label": parsed.get("appearance_label"),
                "tx_power": parsed.get("tx_power"),
                "flags": parsed.get("flags"),
                "pdu_type": parsed.get("pdu_type"),
                "pdu_type_label": parsed.get("pdu_type_label"),
                "contains_scan_response_data": bool(parsed.get("contains_scan_response_data")),
                "extended_advertising_seen": bool(parsed.get("is_extended_advertising")),
                "tx_add_randomized": bool(parsed.get("tx_add_randomized")),
                "rx_add_randomized": bool(parsed.get("rx_add_randomized")),
                "privacy_state": self._privacy_state(parsed, mac),
                "ble_payload": parsed.get("raw_payload"),
                "advertising_payload": parsed.get("advertising_payload"),
                "malformed_ad_structure_count": int(parsed.get("malformed_ad_structure_count") or 0),
                "parse_warnings": parsed.get("parse_warnings") or [],
                "payload_signature": payload_signature,
                "signature_match": parsed.get("signature_match"),
                "device_hint": self._infer_device_type(
                    parsed.get("device_name"),
                    parsed.get("service_uuids"),
                    parsed.get("manufacturer_id"),
                ),
                "rssi": rssi,
                "paired_scan_response": bool(paired_scan_response),
                **heuristics,
            }

            if evidence_quality == "low":
                self.low_evidence_event_count += 1

            cached["vendor"] = event.get("vendor") or cached.get("vendor")
            cached["vendor_source"] = event.get("vendor_source") or cached.get("vendor_source")
            cached["vendor_confidence"] = max(
                float(cached.get("vendor_confidence") or 0.0),
                float(event.get("vendor_confidence") or 0.0),
            )
            cached["device_name"] = event.get("device_name") or cached.get("device_name")
            cached["device_hint"] = event.get("device_hint") or cached.get("device_hint")
            cached["manufacturer_id"] = event.get("manufacturer_id") or cached.get("manufacturer_id")
            cached["manufacturer_company"] = event.get("manufacturer_company") or cached.get("manufacturer_company")
            cached["manufacturer_data"] = event.get("manufacturer_data") or cached.get("manufacturer_data")
            manufacturer_observations = dict(cached.get("manufacturer_observations") or {})
            if event.get("manufacturer_id"):
                manufacturer_observations[event["manufacturer_id"]] = int(manufacturer_observations.get(event["manufacturer_id"]) or 0) + 1
            cached["manufacturer_observations"] = manufacturer_observations
            cached["manufacturer_confirmed"] = bool(cached.get("manufacturer_confirmed") or manufacturer_confirmed)
            cached["service_uuids"] = sorted(
                set(list(cached.get("service_uuids") or []) + list(event.get("service_uuids") or []))
            )
            cached["service_uuid_names"] = sorted(
                set(list(cached.get("service_uuid_names") or []) + list(event.get("service_uuid_names") or []))
            )
            cached["service_data"] = {
                **dict(cached.get("service_data") or {}),
                **dict(event.get("service_data") or {}),
            }
            cached["service_data_keys"] = sorted(
                set(list(cached.get("service_data_keys") or []) + list(event.get("service_data_keys") or []))
            )
            cached["appearance"] = event.get("appearance") or cached.get("appearance")
            cached["appearance_label"] = event.get("appearance_label") or cached.get("appearance_label")
            cached["tx_power"] = event.get("tx_power") if event.get("tx_power") is not None else cached.get("tx_power")
            cached["backend"] = self.backend_id
            cached["last_frequency_mhz"] = event.get("frequency")
            cached["last_rssi"] = rssi
            cached.setdefault("channels", set()).add(channel)
            cached["privacy_state"] = event.get("privacy_state") or cached.get("privacy_state")
            cached.setdefault("observed_pdu_types", set()).add(event.get("pdu_type_label") or "UNKNOWN")
            cached["extended_advertising_seen"] = bool(cached.get("extended_advertising_seen") or event.get("extended_advertising_seen"))
            cached["probable_vendor_family"] = event.get("probable_vendor_family") or cached.get("probable_vendor_family")
            cached["probable_product_family"] = event.get("probable_product_family") or cached.get("probable_product_family")
            if event.get("signature_match"):
                cached["signature_match"] = event.get("signature_match")
            cached["tracker_like"] = bool(cached.get("tracker_like") or event.get("tracker_like"))
            cached["beacon_like"] = bool(cached.get("beacon_like") or event.get("beacon_like"))
            cached["apple_findmy_like"] = bool(cached.get("apple_findmy_like") or event.get("apple_findmy_like"))
            cached["payload_signature"] = event.get("payload_signature") or cached.get("payload_signature")
            cached["best_confidence"] = max(float(cached.get("best_confidence") or 0.0), float(confidence or 0.0))
            cached["best_evidence_score"] = max(float(cached.get("best_evidence_score") or 0.0), float(evidence_score or 0.0))
            cached["latest_evidence_score"] = evidence_score
            cached["evidence_quality"] = evidence_quality if evidence_quality != "low" or not cached.get("evidence_quality") else cached.get("evidence_quality")
            cached["evidence_reasons"] = sorted(
                set(list(cached.get("evidence_reasons") or []) + list(evidence_reasons or []))
            )
            cached["paired_scan_response"] = bool(cached.get("paired_scan_response") or paired_scan_response)
            cached["paired_scan_response_count"] = int(cached.get("paired_scan_response_count") or 0) + (
                1 if paired_scan_response else 0
            )
            cached["ad_structure_count"] = max(int(cached.get("ad_structure_count") or 0), int(parsed.get("ad_structure_count") or 0))
            cached["manufacturer_data_present"] = bool(cached.get("manufacturer_data_present") or event.get("manufacturer_data"))
            cached["service_hint_count"] = max(
                int(cached.get("service_hint_count") or 0),
                len(event.get("service_uuid_names") or []),
            )
            cached["scan_response_seen_count"] = int(cached.get("scan_response_seen_count") or 0) + (
                1 if event.get("contains_scan_response_data") else 0
            )
            cached["crc_valid_count"] = int(cached.get("crc_valid_count") or 0) + (
                1 if event.get("crc_valid") else 0
            )
            trusted_identity, trust_reasons = self._is_trusted_identity(cached, parsed, event)
            cached["trusted_identity"] = trusted_identity
            cached["trust_reasons"] = trust_reasons
            cached["probable_product_family"] = self._infer_product_family(cached)
            cached["trust_score"] = self._compute_trust_score(cached)
            spam_like, spam_confidence, spam_reasons = self._assess_spam_behavior(cached)
            cached["spam_like"] = spam_like
            cached["spam_confidence"] = spam_confidence
            cached["spam_reasons"] = spam_reasons
            event["spam_like"] = bool(spam_like)
            event["spam_confidence"] = spam_confidence
            event["spam_reasons"] = list(spam_reasons or [])
            self._export_packet_record(
                {
                    "timestamp": now,
                    "mac_address": mac,
                    "channel": channel,
                    "frequency_mhz": round(freq / 1e6, 3),
                    "pdu_type_label": parsed.get("pdu_type_label"),
                    "crc_valid": bool(parsed.get("crc_valid")),
                    "confidence": confidence,
                    "evidence_score": evidence_score,
                    "trusted_identity": bool(cached.get("trusted_identity")),
                    "vendor": cached.get("vendor"),
                    "vendor_source": cached.get("vendor_source"),
                    "manufacturer_id": event.get("manufacturer_id"),
                    "manufacturer_company": event.get("manufacturer_company"),
                    "manufacturer_confirmed": bool(cached.get("manufacturer_confirmed")),
                    "device_name": event.get("device_name"),
                    "service_uuids": list(event.get("service_uuids") or []),
                    "service_data_keys": list(event.get("service_data_keys") or []),
                    "privacy_state": event.get("privacy_state"),
                    "paired_scan_response": bool(cached.get("paired_scan_response")),
                    "spam_like": bool(cached.get("spam_like")),
                    "spam_confidence": cached.get("spam_confidence", 0.0),
                    "malformed_ad_structure_count": int(parsed.get("malformed_ad_structure_count") or 0),
                    "parse_warnings": list(parsed.get("parse_warnings") or []),
                }
            )

            try:
                event = self.tracker.process_event(event)
            except Exception:
                print("[DEBUG] Tracker error")
            else:
                tracked = self.tracker.devices.get(event.get("device_id")) if event.get("device_id") else None
                if tracked:
                    cached["address_rotation_count"] = max(0, len(tracked.get("macs", [])) - 1)

            if event.get("pdu_type_label") != "SCAN_RSP":
                self._recent_advertisers.append(
                    {
                        "mac_address": mac,
                        "timestamp": now,
                        "channel": channel,
                        "parsed": dict(parsed),
                        "payload_signature": payload_signature,
                    }
                )

            if cached.get("trusted_identity") or evidence_quality != "low":
                event["trusted_identity"] = bool(cached.get("trusted_identity"))
                event["trust_reasons"] = list(cached.get("trust_reasons") or [])
                event["trust_score"] = cached.get("trust_score")
                event["probable_product_family"] = cached.get("probable_product_family")
                event["signature_match"] = cached.get("signature_match")
                events_batch.append(event)
            else:
                if (
                    event.get("mac_address")
                    and event.get("pdu_type_label") in {"ADV_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND", "SCAN_RSP", "ADV_EXT_IND"}
                ):
                    event["trusted_identity"] = False
                    event["trust_reasons"] = list(cached.get("trust_reasons") or [])
                    event["trust_score"] = cached.get("trust_score")
                    event["probable_product_family"] = "Unknown BLE Device"
                    event["signature_match"] = None
                    event["provisional_identity"] = True
                    events_batch.append(event)

        print(f"[DEBUG] Events before pipeline: {len(events_batch)}")

        events_batch = self._safe_pipeline_stage("Identity", self.identity, events_batch)
        events_batch = self._safe_pipeline_stage("Correlator", self.correlator, events_batch)
        events_batch = self._safe_pipeline_stage("Behavior", self.behavior, events_batch)
        events_batch = self._safe_pipeline_stage("CrossIdentity", self.cross_identity, events_batch)
        events_batch = self._safe_pipeline_stage("Fingerprinting", self.fingerprinting, events_batch)
        events_batch = self._safe_pipeline_stage("Targeting", self.targeting, events_batch)
        events_batch = self._safe_pipeline_stage("Alerts", self.alerts, events_batch)

        print(f"[DEBUG] Events after pipeline: {len(events_batch)}")

        with self._lock:
            self._buffer.extend(events_batch)
            self._history.extend(dict(event) for event in events_batch)
        self.decoded_event_count += len(events_batch)
        if events_batch:
            self.last_event_at = now

        try:
            self.tracker.cleanup()
        except Exception:
            pass

    def _accept_packet(self, parsed: Dict[str, Any], cached: Optional[Dict[str, Any]] = None) -> bool:
        pdu_type = str(parsed.get("pdu_type_label") or "")
        ad_structure_count = int(parsed.get("ad_structure_count") or 0)
        crc_valid = bool(parsed.get("crc_valid"))
        mac = str(parsed.get("mac_address") or "")
        unique_octets = len({octet for octet in mac.split(":") if octet})
        plausible_adv_type = pdu_type in {"ADV_IND", "ADV_NONCONN_IND", "SCAN_RSP", "ADV_SCAN_IND", "ADV_EXT_IND"}
        payload_hint = bool(
            parsed.get("manufacturer_id")
            or parsed.get("manufacturer_company")
            or parsed.get("manufacturer_data")
            or parsed.get("service_uuids")
            or parsed.get("service_data")
            or parsed.get("device_name")
            or parsed.get("appearance") is not None
        )

        if crc_valid:
            return True

        if pdu_type in {"CONNECT_IND", "ADV_DIRECT_IND"}:
            return False

        if plausible_adv_type and payload_hint and unique_octets >= 4:
            return True

        if cached and plausible_adv_type and unique_octets >= 4:
            if float(cached.get("best_evidence_score") or 0.0) >= 0.34:
                return True
            if int(cached.get("seen_count") or 0) >= 3 and bool(cached.get("manufacturer_data_present")):
                return True
            if int(cached.get("scan_response_seen_count") or 0) >= 1 and int(cached.get("service_hint_count") or 0) >= 1:
                return True

        if ad_structure_count == 0 and unique_octets <= 3:
            return False

        if ad_structure_count == 0 and pdu_type in {"ADV_EXT_IND"}:
            return False

        if not payload_hint and ad_structure_count <= 1 and unique_octets <= 4:
            return False

        return True

    def _pair_scan_response(
        self,
        mac: str,
        parsed: Dict[str, Any],
        channel: int,
        timestamp: float,
        payload_signature: str,
    ) -> Optional[Dict[str, Any]]:
        if parsed.get("pdu_type_label") != "SCAN_RSP":
            return None
        best_candidate = None
        best_score = 0
        for candidate in reversed(self._recent_advertisers):
            if candidate.get("channel") != channel:
                continue
            age = timestamp - float(candidate.get("timestamp") or 0.0)
            if age > self.SCAN_RESPONSE_WINDOW_SEC:
                continue
            candidate_parsed = dict(candidate.get("parsed") or {})
            if candidate.get("mac_address") == mac:
                return candidate_parsed
            if payload_signature and candidate.get("payload_signature") == payload_signature:
                return candidate_parsed

            if age > self.RELAXED_SCAN_RESPONSE_WINDOW_SEC:
                continue

            score = 0
            candidate_privacy = self._privacy_state(candidate_parsed, candidate.get("mac_address") or "")
            response_privacy = self._privacy_state(parsed, mac)
            if candidate_privacy == response_privacy:
                score += 2
            if bool(candidate_parsed.get("contains_scan_response_data")) is False:
                score += 1
            if not candidate_parsed.get("device_name") and parsed.get("device_name"):
                score += 1
            candidate_services = set(candidate_parsed.get("service_uuids") or [])
            response_services = set(parsed.get("service_uuids") or [])
            if candidate_services and response_services and candidate_services & response_services:
                score += 2
            if candidate_parsed.get("manufacturer_id") and parsed.get("manufacturer_id") and candidate_parsed.get("manufacturer_id") == parsed.get("manufacturer_id"):
                score += 3

            if score > best_score:
                best_score = score
                best_candidate = candidate_parsed
        return best_candidate if best_score >= 3 else None

    def _is_confirmed_manufacturer(self, parsed: Dict[str, Any], cached: Optional[Dict[str, Any]] = None) -> bool:
        manufacturer_id = str(parsed.get("manufacturer_id") or "").upper()
        manufacturer_company = parsed.get("manufacturer_company")
        manufacturer_data = str(parsed.get("manufacturer_data") or "")
        if not manufacturer_id or not manufacturer_company:
            return False
        prior_count = int(((cached or {}).get("manufacturer_observations") or {}).get(manufacturer_id) or 0)
        if bool(parsed.get("crc_valid")):
            return True
        if len(manufacturer_data) >= 14 and bool(parsed.get("contains_scan_response_data")):
            return True
        if prior_count >= 1 and len(manufacturer_data) >= 10:
            return True
        return prior_count >= 3 and len(manufacturer_data) >= 6

    def _export_packet_record(self, record: Dict[str, Any]) -> None:
        try:
            self.packet_export_path.parent.mkdir(parents=True, exist_ok=True)
            if self.packet_export_count >= self.BLE_EXPORT_MAX_RECORDS and self.packet_export_path.exists():
                lines = self.packet_export_path.read_text(encoding="utf-8").splitlines()
                lines = lines[-(self.BLE_EXPORT_MAX_RECORDS // 2):]
                self.packet_export_path.write_text(
                    "\n".join(lines) + ("\n" if lines else ""),
                    encoding="utf-8",
                )
                self.packet_export_count = len(lines)
            with self.packet_export_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            self.packet_export_count += 1
        except Exception as exc:
            log.debug("[BLE] packet export failed: %s", exc)

    def _merge_adv_data(self, primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(primary or {})
        for key, value in (secondary or {}).items():
            if key in {"service_uuids", "service_uuid_names", "ad_types"}:
                merged[key] = list(dict.fromkeys(list(merged.get(key) or []) + list(value or [])))
            elif key == "service_data":
                merged[key] = {**(merged.get(key) or {}), **(value or {})}
            elif merged.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
                merged[key] = value
        merged["ad_structure_count"] = max(
            int((primary or {}).get("ad_structure_count") or 0),
            int((secondary or {}).get("ad_structure_count") or 0),
        )
        return merged

    def _merge_parsed_packet(self, primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(secondary or {})
        merged.update({key: value for key, value in (primary or {}).items() if value not in (None, "", [], {})})
        adv_data = self._merge_adv_data(
            (secondary or {}).get("adv_data") or {},
            (primary or {}).get("adv_data") or {},
        )
        merged["adv_data"] = adv_data
        for key in (
            "device_name",
            "manufacturer_id",
            "manufacturer_company",
            "manufacturer_data",
            "service_uuids",
            "service_uuid_names",
            "service_data",
            "appearance",
            "appearance_label",
            "flags",
            "tx_power",
            "ad_structure_count",
        ):
            if adv_data.get(key) not in (None, "", [], {}):
                merged[key] = adv_data.get(key)
        merged["contains_scan_response_data"] = True
        return merged

    def _is_trusted_identity(
        self,
        cached: Dict[str, Any],
        parsed: Dict[str, Any],
        event: Dict[str, Any],
    ) -> tuple[bool, List[str]]:
        reasons: List[str] = []
        if bool(parsed.get("crc_valid")) or int(cached.get("crc_valid_count") or 0) > 0:
            reasons.append("crc_valid")
        if event.get("device_name"):
            reasons.append("device_name")
        if event.get("manufacturer_confirmed"):
            reasons.append("manufacturer_data")
        if event.get("service_uuid_names"):
            reasons.append("service_uuid")
        if int(cached.get("ad_structure_count") or 0) >= 2:
            reasons.append("ad_structures")
        if bool(cached.get("paired_scan_response")):
            reasons.append("scan_response_pair")
        if int(cached.get("seen_count") or 0) >= 3 and float(cached.get("best_evidence_score") or 0.0) >= 0.42:
            reasons.append("repeatable")
        strong_evidence = any(
            [
                bool(parsed.get("crc_valid")) or int(cached.get("crc_valid_count") or 0) > 0,
                bool(event.get("manufacturer_confirmed")),
                bool(cached.get("paired_scan_response")),
                bool(event.get("device_name")),
                (
                    int(cached.get("seen_count") or 0) >= 3
                    and (
                        bool(cached.get("service_data_keys"))
                        or (
                            int(cached.get("scan_response_seen_count") or 0) >= 1
                            and int(cached.get("service_hint_count") or 0) >= 1
                        )
                    )
                ),
            ]
        )
        trusted = strong_evidence and (
            float(cached.get("best_evidence_score") or 0.0) >= self.TRUSTED_EVIDENCE_SCORE
            or float(cached.get("best_confidence") or 0.0) >= self.TRUSTED_CONFIDENCE
        ) and bool(reasons)
        return trusted, sorted(set(reasons))

    def _infer_product_family(self, cached: Dict[str, Any]) -> str:
        name = str(cached.get("device_name") or "").lower()
        manufacturer_id = str(cached.get("manufacturer_id") or "").upper()
        service_uuids = {str(uuid).upper() for uuid in (cached.get("service_uuids") or [])}
        appearance = cached.get("appearance")
        tracker_like = bool(cached.get("tracker_like"))
        beacon_like = bool(cached.get("beacon_like"))
        apple_findmy_like = bool(cached.get("apple_findmy_like"))

        if "airtag" in name or "find my" in name or "FD5A" in service_uuids:
            return "Apple AirTag / Find My Tag"
        if manufacturer_id == "0118" or tracker_like:
            return "Tracker Tag"
        if "FEAA" in service_uuids or beacon_like:
            return "BLE Beacon"
        if manufacturer_id == "0133" or "180D" in service_uuids or "heart" in name:
            return "Fitness Wearable"
        if manufacturer_id == "00D2" or (manufacturer_id == "0075" and ("audio" in name or "buds" in name)):
            return "Bluetooth Audio Accessory"
        if manufacturer_id == "004C" and apple_findmy_like:
            return "Apple Find My / Continuity Device"
        if manufacturer_id == "004C":
            return "Apple BLE Device"
        if "1812" in service_uuids:
            return "BLE HID Peripheral"
        if "FE2C" in service_uuids:
            return "Fast Pair Accessory"
        if appearance in {192, 193}:
            return "Smartwatch"
        if appearance in {512, 960}:
            return "Tracker Tag"
        if appearance == 64:
            return "Phone"
        return str(cached.get("probable_product_family") or "Unknown BLE Device")

    # =========================================================================
    def _compute_confidence(self, parsed, adv, rssi, evidence_score: float = 0.0):

        score = 0.4

        if parsed.get("valid"):
            score += 0.2

        if adv:
            score += 0.1

        if rssi is not None:
            score += 0.05

        if parsed.get("pdu_type_label") in {"ADV_IND", "ADV_NONCONN_IND", "SCAN_RSP", "ADV_SCAN_IND", "ADV_EXT_IND"}:
            score += 0.05

        if parsed.get("manufacturer_id") or adv.get("manufacturer_id"):
            score += 0.05
        if parsed.get("crc_valid"):
            score += 0.15
        elif evidence_score < 0.45:
            score -= 0.18
        if evidence_score >= 0.8:
            score += 0.12
        elif evidence_score >= 0.55:
            score += 0.06
        elif evidence_score < 0.25:
            score -= 0.08

        return round(max(0.0, min(score, 1.0)), 3)

    def _compute_evidence_score(self, parsed: Dict[str, Any], adv: Dict[str, Any]) -> tuple[float, str, List[str]]:
        score = 0.15
        reasons: List[str] = []

        ad_structure_count = int(parsed.get("ad_structure_count") or adv.get("ad_structure_count") or 0)
        if ad_structure_count > 0:
            score += min(0.24, ad_structure_count * 0.06)
            reasons.append(f"{ad_structure_count} ad structures")
        malformed_count = int(parsed.get("malformed_ad_structure_count") or adv.get("malformed_ad_structure_count") or 0)
        if malformed_count:
            score -= min(0.3, malformed_count * 0.12)
            reasons.append("malformed ad structure")

        if parsed.get("crc_valid"):
            score += 0.28
            reasons.append("crc valid")
        else:
            score -= 0.06

        if parsed.get("device_name"):
            score += 0.2
            reasons.append("device name")

        if parsed.get("manufacturer_id"):
            score += 0.18
            reasons.append("manufacturer data")
        if parsed.get("manufacturer_company"):
            score += 0.08
            reasons.append("manufacturer company")
        if parsed.get("manufacturer_company") and not parsed.get("manufacturer_id"):
            score -= 0.08

        service_names = parsed.get("service_uuid_names") or adv.get("service_uuid_names") or []
        if service_names:
            score += min(0.1, len(service_names) * 0.05)
            reasons.append("service uuid")
        service_data = parsed.get("service_data") or adv.get("service_data") or {}
        if service_data:
            score += min(0.14, len(service_data) * 0.07)
            reasons.append("service data")

        if parsed.get("appearance"):
            score += 0.08
            reasons.append("appearance")

        if parsed.get("contains_scan_response_data"):
            score += 0.1
            reasons.append("scan response")

        pdu_type = str(parsed.get("pdu_type_label") or "")
        if pdu_type in {"ADV_IND", "ADV_NONCONN_IND", "SCAN_RSP", "ADV_SCAN_IND", "ADV_EXT_IND"}:
            score += 0.06
            reasons.append(pdu_type.lower())

        mac = str(parsed.get("mac_address") or "")
        mac_octets = [octet for octet in mac.split(":") if octet]
        unique_octets = len(set(mac_octets))
        if unique_octets <= 2:
            score -= 0.12
            reasons.append("low mac entropy")

        if not ad_structure_count and not parsed.get("manufacturer_id") and not service_names and not parsed.get("device_name"):
            score -= 0.08
            reasons.append("header only")
        if not parsed.get("crc_valid") and not parsed.get("manufacturer_id") and not service_data and not parsed.get("device_name"):
            score -= 0.12
            reasons.append("weak payload")

        privacy_state = self._privacy_state(parsed, mac) if mac else "unknown"
        if privacy_state == "public" and unique_octets >= 5:
            score += 0.05
            reasons.append("public address")

        score = max(0.0, min(1.0, score))
        if score >= 0.72:
            quality = "high"
        elif score >= 0.45:
            quality = "medium"
        else:
            quality = "low"
        return round(score, 3), quality, reasons

    def _infer_device_type(self, name, uuids, manufacturer):

        if name:
            n = name.lower()

            if "iphone" in n:
                return "phone"
            if "watch" in n:
                return "wearable"
            if "airtag" in n:
                return "tracker"
            if "watch" in n or "fit" in n or "band" in n:
                return "wearable"
            if "tag" in n or "beacon" in n:
                return "beacon"

        if manufacturer and str(manufacturer).startswith("004C"):
            return "apple_device"
        uuid_set = {str(uuid).upper() for uuid in (uuids or [])}
        if "1812" in uuid_set:
            return "hid_device"
        if "180F" in uuid_set:
            return "battery_powered_peripheral"
        if "FEAA" in uuid_set:
            return "eddystone_beacon"

        return "unknown"

    def _privacy_state(self, parsed: Dict[str, Any], mac: str) -> str:
        if parsed.get("tx_add_randomized"):
            return "randomized"
        try:
            first_octet = int(mac.split(":")[0], 16)
        except Exception:
            return "unknown"
        return "randomized" if first_octet & 0b10 else "public"

    def _payload_signature(self, parsed: Dict[str, Any], adv_data: Dict[str, Any]) -> str:
        parts = [
            str(parsed.get("manufacturer_id") or ""),
            ",".join(sorted(parsed.get("service_uuids") or [])),
            ",".join(sorted((parsed.get("service_data") or {}).keys())),
            str(parsed.get("appearance") or ""),
            str(parsed.get("device_name") or "")[:24].lower(),
            str(parsed.get("pdu_type_label") or ""),
        ]
        raw = "|".join(parts)
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def _classify_ble_event(self, parsed: Dict[str, Any], adv_data: Dict[str, Any]) -> Dict[str, Any]:
        manufacturer_id = str(parsed.get("manufacturer_id") or "").upper()
        manufacturer_company = parsed.get("manufacturer_company") or adv_data.get("manufacturer_company")
        service_uuids = {str(uuid).upper() for uuid in (parsed.get("service_uuids") or [])}
        name = str(parsed.get("device_name") or "").lower()
        privacy_state = self._privacy_state(parsed, parsed.get("mac_address") or "")
        signature_match = parsed.get("signature_match") or self.knowledge_base.match_product(parsed, adv_data)
        tracker_like = False
        beacon_like = False
        apple_findmy_like = False
        probable_vendor_family = manufacturer_company or parsed.get("vendor")
        probable_product_family = "Unknown BLE Device"

        if signature_match:
            probable_vendor_family = signature_match.get("vendor") or probable_vendor_family
            probable_product_family = signature_match.get("label") or probable_product_family
            tracker_like = signature_match.get("role") == "tracker_tag"
            beacon_like = signature_match.get("role") == "beacon"
            apple_findmy_like = probable_product_family in {"Apple AirTag", "Apple Find My Accessory"}

        if "FEAA" in service_uuids:
            beacon_like = True
            probable_product_family = "Eddystone Beacon"
            probable_vendor_family = probable_vendor_family or "Google Ecosystem"
        if manufacturer_id == "0118":
            tracker_like = True
            probable_product_family = "Tile-style Tracker"
            probable_vendor_family = probable_vendor_family or "Tile"
        if manufacturer_id == "004C":
            probable_vendor_family = "Apple"
            if "airtag" in name:
                tracker_like = True
                apple_findmy_like = True
                probable_product_family = "Apple AirTag"
            elif privacy_state == "randomized" and parsed.get("pdu_type_label") in {"ADV_IND", "ADV_NONCONN_IND", "ADV_EXT_IND"}:
                apple_findmy_like = True
                probable_product_family = "Apple Find My / Continuity Device"
            else:
                probable_product_family = "Apple BLE Device"
        if "beacon" in name or "eddystone" in name:
            beacon_like = True
            probable_product_family = "BLE Beacon"
        if "tag" in name and probable_product_family == "Unknown BLE Device":
            tracker_like = True
            probable_product_family = "BLE Tracker"
        if manufacturer_id == "004C" and privacy_state == "randomized":
            tracker_like = tracker_like or parsed.get("pdu_type_label") in {"ADV_IND", "ADV_NONCONN_IND", "ADV_EXT_IND"}

        return {
            "tracker_like": tracker_like,
            "beacon_like": beacon_like,
            "apple_findmy_like": apple_findmy_like,
            "probable_vendor_family": probable_vendor_family,
            "probable_product_family": probable_product_family,
            "signature_match": signature_match,
        }

    def _normalize_mac(self, mac: str) -> Optional[str]:

        if not mac:
            return None

        clean = mac.upper().replace(":", "").replace("-", "")

        if len(clean) < 12:
            return None

        clean = clean[:12]

        return ":".join(clean[i:i+2] for i in range(0, 12, 2))

    def _load_oui(self, path: str) -> Dict[str, str]:

        db = {}

        if not os.path.exists(path):
            return db

        with open(path, "r", errors="ignore") as f:
            for line in f:

                if "(base 16)" in line or "(hex)" in line:

                    parts = line.split("(base 16)") if "(base 16)" in line else line.split("(hex)")

                    if len(parts) == 2:
                        prefix = parts[0].strip().replace("-", "").upper()
                        vendor = parts[1].strip()

                        db[prefix[:6]] = vendor

        return db

    def _resolve_vendor(self, mac: str) -> Optional[str]:

        if not mac:
            return None

        return self.oui_db.get(mac.replace(":", "")[:6])

    def _freq_to_channel(self, freq: float) -> int:

        mhz = freq / 1e6

        if abs(mhz - 2402) < 2:
            return 37
        elif abs(mhz - 2426) < 2:
            return 38
        elif abs(mhz - 2480) < 2:
            return 39

        return 37
