# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         zigbee_decoder_worker.py
# VERSION:      v8.0.0 (PRODUCTION SIGINT PIPELINE - GNU RADIO INTEGRATED)
# UPDATED:      2026-03-25
# =============================================================================

import time
import numpy as np
from collections import defaultdict

# -----------------------------------------------------------------------------
# CORE IMPORTS
# -----------------------------------------------------------------------------
from backend.intel.zigbee.zigbee_phy_engine import ZigbeePHYEngine
from backend.intel.zigbee.zigbee_ieee802154_decoder import ZigbeeIEEE802154Decoder
from backend.intel.zigbee.zigbee_ieee802154_flowgraph import ZigbeeFlowgraph

# -----------------------------------------------------------------------------
# OPTIONAL IMPORTS
# -----------------------------------------------------------------------------
try:
    from scapy.layers.dot15d4 import Dot15d4
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from backend.intel.behavior.behavior_profiler import BehaviorProfiler
    BEHAVIOR_AVAILABLE = True
except Exception:
    BEHAVIOR_AVAILABLE = False

try:
    from backend.intel.zigbee.zigbee_role_classifier import ZigbeeRoleClassifier
    ROLE_AVAILABLE = True
except Exception:
    ROLE_AVAILABLE = False


class ZigbeeDecoderWorker:
    """
    PRODUCTION Zigbee Decoder Worker

    Dual pipeline architecture:
    1. PRIMARY → GNU Radio Flowgraph + Real DSSS Decoder (HIGH ACCURACY)
    2. FALLBACK → Custom PHY Engine (RESILIENCE)

    Responsibilities:
    - SDR capture (via GNU Radio)
    - DSSS decoding (real IEEE 802.15.4)
    - Frame parsing
    - Behavior intelligence
    - Role classification
    """

    def __init__(self, sdr=None, sample_rate=2_000_000):

        self.sdr = sdr
        self.sample_rate = sample_rate

        # ---------------------------------------------------------
        # PRIMARY PIPELINE (REAL DECODER)
        # ---------------------------------------------------------
        self.decoder = ZigbeeIEEE802154Decoder()

        # ---------------------------------------------------------
        # FALLBACK PIPELINE (LEGACY SAFETY)
        # ---------------------------------------------------------
        self.phy = ZigbeePHYEngine(sample_rate=sample_rate)

        # ---------------------------------------------------------
        # STATE
        # ---------------------------------------------------------
        self.event_count = 0
        self.device_stats = defaultdict(int)

        self.debug = False

        # ---------------------------------------------------------
        # BEHAVIOR ENGINE
        # ---------------------------------------------------------
        if BEHAVIOR_AVAILABLE:
            self.behavior = BehaviorProfiler()
            print("🧠 [ZIGBEE] Behavior engine attached")
        else:
            self.behavior = None
            print("⚠️ [ZIGBEE] Behavior engine NOT available")

        # ---------------------------------------------------------
        # ROLE CLASSIFIER
        # ---------------------------------------------------------
        if ROLE_AVAILABLE:
            self.role_classifier = ZigbeeRoleClassifier()
            print("🧭 [ZIGBEE] Role classifier attached")
        else:
            self.role_classifier = None
            print("⚠️ [ZIGBEE] Role classifier NOT available")

        print("📡 [ZIGBEE] Decoder initialized (Scapy:", SCAPY_AVAILABLE, ")")

    # -----------------------------------------------------------------------------
    # MAIN LOOP
    # -----------------------------------------------------------------------------
    def run(self, duration=10, freq=2405e6):

        start = time.time()
        events = []

        # ---------------------------------------------------------
        # START GNU RADIO FLOWGRAPH
        # ---------------------------------------------------------
        try:
            flow = ZigbeeFlowgraph(freq=freq, samp_rate=4e6, gain=40)
            flow.start()
            time.sleep(0.5)  # warmup
        except Exception as e:
            print("❌ [ZIGBEE] Flowgraph init failed:", e)
            return []

        # ---------------------------------------------------------
        # CAPTURE LOOP
        # ---------------------------------------------------------
        while time.time() - start < duration:

            try:
                chips = flow.get_chips()
                flow.clear()
            except Exception:
                continue

            if chips is None or len(chips) < 2048:
                continue

            if self.debug:
                print(f"[DEBUG] Chips: {len(chips)}")

            # =====================================================
            # PRIMARY PIPELINE (REAL DSSS DECODER)
            # =====================================================
            frames = []
            try:
                frames = self.decoder.decode(chips)
            except Exception as e:
                if self.debug:
                    print("[DEBUG] Decoder error:", e)

            # =====================================================
            # FALLBACK PIPELINE (ONLY IF PRIMARY FAILS)
            # =====================================================
            if not frames:
                if self.debug:
                    print("[DEBUG] Falling back to PHY engine")

                iq_samples = self._capture_samples()

                if iq_samples is not None:
                    frame_bytes = self.phy.process(iq_samples)

                    if self._validate_frame(frame_bytes):
                        fallback_event = self._parse_frame(frame_bytes)
                        if fallback_event:
                            events.append(fallback_event)
                            self._post_process(fallback_event)

                continue

            # =====================================================
            # PROCESS REAL FRAMES
            # =====================================================
            for frame in frames:

                event = self._normalize_frame(frame)

                if not event:
                    continue

                events.append(event)

                self._post_process(event)

                if self.debug:
                    print("[ZIGBEE EVENT]", event)

        # ---------------------------------------------------------
        # CLEANUP (CRITICAL)
        # ---------------------------------------------------------
        try:
            flow.stop()
            flow.wait()
        except Exception:
            pass

        return events

    # -----------------------------------------------------------------------------
    # POST PROCESS (BEHAVIOR + ROLE + STATS)
    # -----------------------------------------------------------------------------
    def _post_process(self, event):

        # Behavior
        if self.behavior:
            try:
                self.behavior.process_event(event)
            except Exception:
                pass

        # Role
        if self.role_classifier:
            try:
                self.role_classifier.process_event(event)
            except Exception:
                pass

        self._update_stats(event)

    # -----------------------------------------------------------------------------
    # NORMALIZE FRAME (FROM DECODER)
    # -----------------------------------------------------------------------------
    def _normalize_frame(self, frame):

        try:
            src = frame.get("src_addr")
            dst = frame.get("dest_addr")
            pan = frame.get("dest_pan")

            device_id = f"{pan}_{src}"

            return {
                "timestamp": time.time(),
                "pan_id": pan,
                "src_addr": self._normalize_addr(src),
                "dst_addr": self._normalize_addr(dst),
                "frame_type": frame.get("frame_type"),
                "device_id": device_id,
                "protocol": "zigbee",
                "confidence": frame.get("confidence", 0.9)
            }

        except Exception:
            return None

    # -----------------------------------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------------------------------
    def _validate_frame(self, frame_bytes):

        if not frame_bytes:
            return False

        if len(frame_bytes) < 5:
            return False

        if len(frame_bytes) > 256:
            return False

        return True

    # -----------------------------------------------------------------------------
    # FALLBACK SDR CAPTURE
    # -----------------------------------------------------------------------------
    def _capture_samples(self):

        if not self.sdr:
            return None

        try:
            return self.sdr.read_samples()
        except Exception:
            return None

    # -----------------------------------------------------------------------------
    # PARSER (SCAPY OR FALLBACK)
    # -----------------------------------------------------------------------------
    def _parse_frame(self, frame_bytes):

        if not SCAPY_AVAILABLE:
            return self._fallback_parse(frame_bytes)

        try:
            pkt = Dot15d4(frame_bytes)

            pan_id = getattr(pkt, "dest_panid", None)
            src_addr = getattr(pkt, "src_addr", None)
            dst_addr = getattr(pkt, "dest_addr", None)

            device_id = f"{pan_id}_{src_addr}"

            return {
                "timestamp": time.time(),
                "pan_id": pan_id,
                "src_addr": self._normalize_addr(src_addr),
                "dst_addr": self._normalize_addr(dst_addr),
                "device_id": device_id,
                "protocol": "zigbee",
                "confidence": 0.7
            }

        except Exception:
            return self._fallback_parse(frame_bytes)

    # -----------------------------------------------------------------------------
    def _fallback_parse(self, frame_bytes):

        try:
            pan_id = int.from_bytes(frame_bytes[3:5], "little")
            src_addr = int.from_bytes(frame_bytes[5:7], "little")

            return {
                "timestamp": time.time(),
                "pan_id": hex(pan_id),
                "src_addr": hex(src_addr),
                "device_id": f"{hex(pan_id)}_{hex(src_addr)}",
                "protocol": "zigbee",
                "confidence": 0.5
            }

        except Exception:
            return None

    # -----------------------------------------------------------------------------
    def _normalize_addr(self, addr):
        if addr is None:
            return None
        try:
            return hex(addr)
        except Exception:
            return str(addr)

    # -----------------------------------------------------------------------------
    def _update_stats(self, event):

        self.event_count += 1

        device_id = event.get("device_id")
        if device_id:
            self.device_stats[device_id] += 1

    # -----------------------------------------------------------------------------
    def get_summary(self):

        behavior_profiles = {}
        behavior_active = False
        roles = {}

        if self.behavior:
            try:
                behavior_profiles = self.behavior.get_profiles()
                behavior_active = len(behavior_profiles) > 0
            except Exception:
                pass

        if self.role_classifier and behavior_profiles:
            try:
                roles = self.role_classifier.get_roles(behavior_profiles)
            except Exception:
                pass

        return {
            "events": self.event_count,
            "devices": len(self.device_stats),
            "top_devices": sorted(
                self.device_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "behavior_profiles": behavior_profiles,
            "behavior_active": behavior_active,
            "roles": roles
        }
