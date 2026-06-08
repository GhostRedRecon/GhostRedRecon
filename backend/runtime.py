# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/runtime.py
# VERSION:      v20.0.0 (SIGINT ORCHESTRATOR — UNIFIED FINGERPRINT + IDENTITY SAFE)
# UPDATED:      2026-03-24
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# FastAPI Application
#     ↓
# app.state.runtime
#     ↓
# Runtime  ← THIS FILE (SYSTEM ORCHESTRATOR)
#     ├── SDRController
#     ├── LiveFFT
#     ├── SignalEngine
#     ├── ReconEngine
#     ├── RFProtocolFingerprintEngine
#     ├── RFHardwareFingerprintEngine
#     ├── RFBehaviorFingerprintEngine
#     ├── UnifiedFingerprintEngine
#     ├── RFIdentityResolver
#     ├── BLEIdentityEngine
#     ├── RFDeviceFusionEngine
#     ├── RFDeviceIntelligenceEngine
#     └── SessionController
#
# FULL SIGINT DATA FLOW
# -----------------------------------------------------------------------------
# SDR → FFT → Recon → Signal
#     → Unified Fingerprint Intelligence
#     → Identity Resolution
#     → BLE Identity Extraction
#     → Device Fusion
#     → Device Intelligence
#     → API / Validator / UI
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Runtime is the SINGLE SYSTEM ORCHESTRATOR of GhostRecon.
#
# It ensures:
# ✔ correct dependency wiring
# ✔ coherent Phase 1 / 2 / 3 / 4 pipeline activation
# ✔ fingerprint + identity intelligence is executed before fusion
# ✔ API-visible system truth remains stable
# ✔ backward compatibility is preserved
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ initialize all live engines
# ✔ wire dependencies across the SIGINT pipeline
# ✔ preserve singleton runtime behavior
# ✔ expose stable runtime getters used elsewhere
#
# FINGERPRINT RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ build protocol / hardware / behavior fingerprint engines
# ✔ build unified fingerprint wrapper
# ✔ execute unified fingerprinting before identity + fusion
# ✔ propagate fingerprint data into emitters/devices safely
#
# IDENTITY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ build identity resolver when available
# ✔ build BLE identity engine when available
# ✔ resolve vendor / product hints from enriched signals
# ✔ inject BLE identities into fusion engine safely
#
# FUSION / INTELLIGENCE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ execute device fusion
# ✔ execute device intelligence
# ✔ feed enriched device context back into SignalEngine
#
# SAFETY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ optional engines must never crash pipeline
# ✔ missing imports must degrade gracefully
# ✔ runtime state queries must remain safe
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. SINGLE SOURCE OF TRUTH
#    SignalEngine remains the live signal truth layer.
#
# 2. NON-BREAKING EVOLUTION
#    Existing public runtime attributes and getters remain intact.
#
# 3. FAIL-SAFE OPTIONAL LAYERS
#    Fingerprint / identity / intelligence engines are optional.
#
# 4. STRICT PIPELINE ORDER
#    Fingerprinting and identity must happen before fusion.
#
# 5. ADDITIVE INTELLIGENCE
#    New intelligence augments signals/devices; it never replaces core truth.
#
# 6. OBSERVABILITY
#    Import/init failures should be visible in logs/console, not silent black holes.
#
# =============================================================================
# 📦 RUNTIME ATTRIBUTE SCHEMA
# =============================================================================
#
# runtime.sdr
# runtime.fft
# runtime.signal
# runtime.recon
# runtime.protocol_fingerprint_engine
# runtime.hardware_fingerprint_engine
# runtime.behavior_fingerprint_engine
# runtime.fingerprint_engine
# runtime.identity_resolver
# runtime.ble_identity
# runtime.device_fusion
# runtime.device_fusion_engine
# runtime.device_intelligence
# runtime.device_intelligence_engine
# runtime.session_controller
# runtime.session
#
# =============================================================================
# 🔍 RUNTIME BEHAVIOR
# =============================================================================
#
# Construction Order
# -----------------------------------------------------------------------------
# SDR → FFT → Signal → Recon
#     → fingerprint engines
#     → unified fingerprint engine
#     → identity resolver
#     → BLE identity
#     → device fusion
#     → device intelligence
#     → session controller
#
# run_device_fusion()
# -----------------------------------------------------------------------------
# 1. Pull active emitters
# 2. Pull top signals
# 3. Run unified fingerprint engine (or legacy fallback engines)
# 4. Run identity resolver on signals
# 5. Run BLE identity extraction and ingest into fusion
# 6. Propagate signal fingerprints into emitters
# 7. Run device fusion
# 8. Normalize fusion result
# 9. Propagate fingerprint/vendor/product fields into devices
# 10. Run device intelligence
# 11. Optionally enrich devices
# 12. Feed devices back into SignalEngine
#
# =============================================================================
# 🔄 CHANGE LOG
# =============================================================================
#
# v20.0.0
# ✔ Fixed unified fingerprint orchestration path
# ✔ Added safe identity resolver integration
# ✔ Added fingerprint propagation from signals → emitters → devices
# ✔ Added safer BLE identity normalization
# ✔ Added visible import/init warnings for optional engines
# ✔ Preserved existing runtime attributes and getters
#
# =============================================================================
# 🧠 IMPORTANT NOTES
# =============================================================================
#
# - This is a CORE SYSTEM FILE. Stability matters more than cleverness.
# - Optional imports intentionally fail safe, but now emit useful warnings.
# - Unified fingerprint engine wraps existing engines; it does not replace them.
# - This file does NOT remove any existing functionality.
#
# =============================================================================

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


from backend.sdr.sdr_controller import SDRController
from backend.fft.live_fft import LiveFFT
from backend.recon.core.recon_engine import ReconEngine
from backend.intel.signal_engine import SignalEngine
from backend.intel.correlation.multiband_correlation_engine import MultiBandCorrelationEngine
from backend.session.session_controller import SessionController
from backend.recon.intelligence.device_fusion import RFDeviceFusionEngine
from backend.integrations.rtl433_manager import RTL433Manager
from backend.integrations.hackrf_sweep_manager import HackRFSweepManager
from backend.integrations.wifi_mk7 import WiFiMK7Controller
from backend.integrations.ble_nr5_controller import BLENR5Controller
from backend.integrations.hunt_drones_controller import HuntDronesController


# =============================================================================
# OPTIONAL IMPORTS (SAFE + VISIBLE)
# =============================================================================
try:
    from backend.recon.protocols.protocol_fingerprint import (
        ProtocolFingerprintEngine as RFProtocolFingerprintEngine,
    )
except Exception as e:
    print(f"⚠️ [RUNTIME] ProtocolFingerprintEngine import failed → {e}")
    RFProtocolFingerprintEngine = None

try:
    from backend.recon.fingerprinting.hardware_fingerprint import RFHardwareFingerprintEngine
except Exception as e:
    print(f"⚠️ [RUNTIME] RFHardwareFingerprintEngine import failed → {e}")
    RFHardwareFingerprintEngine = None

try:
    from backend.recon.intelligence.behavior_engine import (
        RFBehaviorEngine as RFBehaviorFingerprintEngine,
    )
except Exception as e:
    print(f"⚠️ [RUNTIME] RFBehaviorEngine import failed → {e}")
    RFBehaviorFingerprintEngine = None

try:
    from backend.recon.fingerprinting.unified_fingerprint_engine import UnifiedFingerprintEngine
except Exception as e:
    print(f"⚠️ [RUNTIME] UnifiedFingerprintEngine import failed → {e}")
    UnifiedFingerprintEngine = None

try:
    from backend.intel.identity.rf_identity_resolver import RFIdentityResolver
except Exception as e:
    print(f"ℹ️ [RUNTIME] RFIdentityResolver unavailable → {e}")
    RFIdentityResolver = None

try:
    from backend.intel.identity.ble_identity_engine import BLEIdentityEngine
except Exception as e:
    print(f"⚠️ [RUNTIME] BLEIdentityEngine import failed → {e}")
    BLEIdentityEngine = None

try:
    from backend.recon.intelligence.ble_device_intelligence import BLEDeviceIntelligenceEngine
except Exception as e:
    print(f"⚠️ [RUNTIME] BLEDeviceIntelligenceEngine import failed → {e}")
    BLEDeviceIntelligenceEngine = None

try:
    from backend.recon.intelligence.zigbee_device_intelligence import ZigbeeDeviceIntelligenceEngine
except Exception as e:
    print(f"⚠️ [RUNTIME] ZigbeeDeviceIntelligenceEngine import failed → {e}")
    ZigbeeDeviceIntelligenceEngine = None

try:
    from backend.recon.intelligence.lora_device_intelligence import LoRaDeviceIntelligenceEngine
except Exception as e:
    print(f"⚠️ [RUNTIME] LoRaDeviceIntelligenceEngine import failed → {e}")
    LoRaDeviceIntelligenceEngine = None

try:
    from backend.recon.intelligence.device_intelligence import (
        RFDeviceIntelligenceEngine as DeviceIntelligence,
    )
except Exception as e:
    print(f"⚠️ [RUNTIME] RFDeviceIntelligenceEngine import failed → {e}")
    DeviceIntelligence = None


# =============================================================================
# 🧠 RUNTIME CLASS
# =============================================================================
class Runtime:
    VERSION = "20.0.0"
    RF_EVENT_LIMIT = 80

    def __init__(self):

        print("🧠 [RUNTIME] Initializing system...")

        try:
            # -----------------------------------------------------------------
            # SDR
            # -----------------------------------------------------------------
            self.sdr = SDRController()
            self._validate_sdr_interface()

            # -----------------------------------------------------------------
            # FFT
            # -----------------------------------------------------------------
            self.fft = LiveFFT(self.sdr)

            # -----------------------------------------------------------------
            # SIGNAL
            # -----------------------------------------------------------------
            self.signal = SignalEngine()
            self._rf_events: List[Dict[str, Any]] = []
            self._last_rf_signature: tuple[Any, ...] | None = None

            # -----------------------------------------------------------------
            # RECON
            # -----------------------------------------------------------------
            self.recon = ReconEngine(signal_engine=self.signal)

            # -----------------------------------------------------------------
            # FINGERPRINT ENGINES (INDIVIDUAL)
            # -----------------------------------------------------------------
            self.protocol_fingerprint_engine = self._build(RFProtocolFingerprintEngine)
            self.hardware_fingerprint_engine = self._build(RFHardwareFingerprintEngine)
            self.behavior_fingerprint_engine = self._build(RFBehaviorFingerprintEngine)

            # -----------------------------------------------------------------
            # UNIFIED FINGERPRINT ENGINE (WRAPPER)
            # -----------------------------------------------------------------
            self.fingerprint_engine = self._build_unified_fingerprint()

            # -----------------------------------------------------------------
            # IDENTITY RESOLUTION
            # -----------------------------------------------------------------
            self.identity_resolver = self._build(RFIdentityResolver)
            self.ble_identity = self._build(BLEIdentityEngine)

            # -----------------------------------------------------------------
            # DEVICE FUSION
            # -----------------------------------------------------------------
            self.device_fusion = RFDeviceFusionEngine()
            self.device_fusion_engine = self.device_fusion
            self.correlation_engine = MultiBandCorrelationEngine()
            self.ble_device_intelligence = self._build(BLEDeviceIntelligenceEngine)
            self.zigbee_device_intelligence = self._build(ZigbeeDeviceIntelligenceEngine)
            self.lora_device_intelligence = self._build(LoRaDeviceIntelligenceEngine)

            # -----------------------------------------------------------------
            # DEVICE INTELLIGENCE
            # -----------------------------------------------------------------
            self.device_intelligence = self._build_optional_device_intelligence()
            self.device_intelligence_engine = self.device_intelligence

            # -----------------------------------------------------------------
            # SIGNAL LINK
            # -----------------------------------------------------------------
            if hasattr(self.signal, "set_device_fusion"):
                try:
                    self.signal.set_device_fusion(self.device_fusion)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] set_device_fusion failed → {e}")

            # -----------------------------------------------------------------
            # SESSION
            # -----------------------------------------------------------------
            self.session_controller = self._build_session_controller()
            self.session = self.session_controller
            self.rtl433 = RTL433Manager()
            self.hackrf_sweep = HackRFSweepManager()
            self.wifi_mk7 = WiFiMK7Controller()
            self.ble_nr5 = BLENR5Controller()
            self.hunt_drones = HuntDronesController(runtime=self)

            print("✅ [RUNTIME] Initialization complete")

        except Exception as e:
            print(f"🔥 [RUNTIME] INIT FAILED → {e}")
            raise

    def record_rf_event(
        self,
        category: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ) -> None:
        event = {
            "timestamp": time.time(),
            "category": str(category or "runtime"),
            "severity": str(severity or "info"),
            "message": str(message or "").strip(),
            "details": details or {},
        }
        self._rf_events.append(event)
        if len(self._rf_events) > self.RF_EVENT_LIMIT:
            self._rf_events = self._rf_events[-self.RF_EVENT_LIMIT :]

    def observe_rf_health(self, health: Dict[str, Any]) -> None:
        if not isinstance(health, dict):
            return

        signature = (
            health.get("sdr_connection_state"),
            bool(health.get("session_active")),
            health.get("sdr_freq_mhz"),
            bool(health.get("sdr_streaming_confirmed")),
        )
        if signature == self._last_rf_signature:
            return

        self._last_rf_signature = signature
        state = str(health.get("sdr_connection_state") or "unknown")
        freq = health.get("sdr_freq_mhz")
        message = state.replace("_", " ")
        if freq is not None:
            message = f"{message} @ {freq} MHz"
        detail = {
            "state": state,
            "freq_mhz": freq,
            "session_active": bool(health.get("session_active")),
            "pipeline_ready": bool(health.get("pipeline_ready")),
        }
        if health.get("sdr_fault_reason"):
            detail["reason"] = health.get("sdr_fault_reason")
        severity = "error" if state in {"disconnected", "stream_process_down", "stream_stalled", "fft_missing"} else "info"
        self.record_rf_event("rf_health", message, detail, severity=severity)

    def get_rf_event_timeline(self, limit: int = 20) -> List[Dict[str, Any]]:
        if limit <= 0:
            return []
        return list(self._rf_events[-limit:])

    # =========================================================================
    # BUILDERS
    # =========================================================================
    def _build(self, cls):
        if cls is None:
            return None
        try:
            return cls()
        except Exception as e:
            print(f"⚠️ [RUNTIME] build failed for {getattr(cls, '__name__', cls)} → {e}")
            return None

    def _build_unified_fingerprint(self):

        if UnifiedFingerprintEngine is None:
            return None

        try:
            return UnifiedFingerprintEngine(
                protocol_engine=self.protocol_fingerprint_engine,
                hardware_engine=self.hardware_fingerprint_engine,
                behavior_engine=self.behavior_fingerprint_engine,
            )
        except Exception as e:
            print(f"⚠️ [RUNTIME] UnifiedFingerprintEngine init failed → {e}")
            return None

    def _build_optional_device_intelligence(self):

        if DeviceIntelligence is None:
            return None

        try:
            return DeviceIntelligence()
        except Exception:
            try:
                return DeviceIntelligence(device_fusion=self.device_fusion)
            except Exception as e:
                print(f"⚠️ [RUNTIME] DeviceIntelligence init failed → {e}")
                return None

    def _build_session_controller(self):

        base_kwargs = {
            "sdr_controller": self.sdr,
            "fft_engine": self.fft,
            "recon_engine": self.recon,
            "signal_engine": self.signal,
        }

        try:
            return SessionController(runtime=self, **base_kwargs)
        except TypeError:
            controller = SessionController(**base_kwargs)
            setattr(controller, "runtime", self)
            return controller

    # =========================================================================
    # VALIDATION
    # =========================================================================
    def _validate_sdr_interface(self):

        required = ["start", "stop", "get_state", "is_healthy"]

        for method_name in required:
            if not hasattr(self.sdr, method_name):
                raise RuntimeError(f"SDR missing: {method_name}")

    # =========================================================================
    # DEVICE FUSION + FINGERPRINT PIPELINE
    # =========================================================================
    def run_device_fusion(self) -> List[Dict[str, Any]]:

        try:
            emitters = self.signal.get_active_emitters()
            if not emitters:
                return []

            signals: List[Dict[str, Any]] = []
            if hasattr(self.signal, "get_top_signals"):
                try:
                    signals = self.signal.get_live_signals(200)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] get_top_signals failed → {e}")
                    signals = []

            # -------------------------------------------------------------
            # UNIFIED FINGERPRINT PIPELINE
            # -------------------------------------------------------------
            if self.fingerprint_engine:
                try:
                    self.fingerprint_engine.process(signals)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] unified fingerprint failed → {e}")
            else:
                # Legacy fallback preserves existing behavior
                for engine in [
                    self.protocol_fingerprint_engine,
                    self.hardware_fingerprint_engine,
                    self.behavior_fingerprint_engine,
                ]:
                    if engine and hasattr(engine, "process"):
                        try:
                            engine.process(signals)
                        except Exception as e:
                            print(f"⚠️ [RUNTIME] legacy fingerprint engine failed → {e}")

            # -------------------------------------------------------------
            # IDENTITY RESOLVER (VENDOR / PRODUCT HINTS)
            # -------------------------------------------------------------
            if self.identity_resolver and hasattr(self.identity_resolver, "process"):
                try:
                    self.identity_resolver.process(signals)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] identity resolver failed → {e}")

            # -------------------------------------------------------------
            # BLE IDENTITY EXTRACTION
            # -------------------------------------------------------------
            if self.ble_identity:
                try:
                    identities = self.ble_identity.process(signals)
                    normalized_identities = self._normalize_identity_result(identities)

                    for identity in normalized_identities:
                        try:
                            self.device_fusion.ingest_identity(identity)
                        except Exception as e:
                            print(f"⚠️ [RUNTIME] ingest_identity failed → {e}")

                except Exception as e:
                    print(f"⚠️ [RUNTIME] BLE identity failed → {e}")

            # -------------------------------------------------------------
            # PROPAGATE SIGNAL-LEVEL FINGERPRINT INTO EMITTERS
            # -------------------------------------------------------------
            self._propagate_signal_intelligence_to_emitters(emitters, signals)

            # -------------------------------------------------------------
            # BLE EMITTER INTELLIGENCE
            # -------------------------------------------------------------
            if self.ble_device_intelligence and hasattr(self.ble_device_intelligence, "enrich_emitters"):
                try:
                    enriched_emitters = self.ble_device_intelligence.enrich_emitters(emitters)
                    if isinstance(enriched_emitters, list):
                        emitters = enriched_emitters
                except Exception as e:
                    print(f"⚠️ [RUNTIME] BLE emitter intelligence failed → {e}")

            if self.zigbee_device_intelligence and hasattr(self.zigbee_device_intelligence, "enrich_emitters"):
                try:
                    enriched_emitters = self.zigbee_device_intelligence.enrich_emitters(emitters)
                    if isinstance(enriched_emitters, list):
                        emitters = enriched_emitters
                except Exception as e:
                    print(f"⚠️ [RUNTIME] Zigbee emitter intelligence failed → {e}")

            if self.lora_device_intelligence and hasattr(self.lora_device_intelligence, "enrich_emitters"):
                try:
                    enriched_emitters = self.lora_device_intelligence.enrich_emitters(emitters)
                    if isinstance(enriched_emitters, list):
                        emitters = enriched_emitters
                except Exception as e:
                    print(f"⚠️ [RUNTIME] LoRa emitter intelligence failed → {e}")

            # -------------------------------------------------------------
            # FUSION
            # -------------------------------------------------------------
            result = self.device_fusion.fuse(emitters)
            devices = self._normalize_fusion_result(result)

            if not devices:
                return []

            # -------------------------------------------------------------
            # PROPAGATE FINGERPRINT / VENDOR / PRODUCT TO DEVICES
            # -------------------------------------------------------------
            self._propagate_emitter_intelligence_to_devices(devices, emitters)

            # -------------------------------------------------------------
            # DEVICE INTELLIGENCE
            # -------------------------------------------------------------
            if self.device_intelligence and hasattr(self.device_intelligence, "analyze_ecosystem"):
                try:
                    edges = []
                    if hasattr(self.device_fusion, "get_edges"):
                        try:
                            edges = self.device_fusion.get_edges()
                        except Exception:
                            edges = []

                    intel = self.device_intelligence.analyze_ecosystem(devices, edges)

                    for device in devices:
                        device["intelligence"] = intel

                except Exception as e:
                    print(f"⚠️ [RUNTIME] device intelligence failed → {e}")

            # -------------------------------------------------------------
            # OPTIONAL ENRICHMENT
            # -------------------------------------------------------------
            devices = self._enrich_devices_if_possible(devices)

            # -------------------------------------------------------------
            # MULTI-BAND CORRELATION
            # -------------------------------------------------------------
            correlations: List[Dict[str, Any]] = []
            if self.correlation_engine:
                try:
                    correlations = self.correlation_engine.process(signals, devices)
                    self._attach_correlation_context(devices, correlations)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] correlation engine failed → {e}")

            # -------------------------------------------------------------
            # FEEDBACK LOOP
            # -------------------------------------------------------------
            if hasattr(self.signal, "update_device_context"):
                try:
                    self.signal.update_device_context(devices)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] update_device_context failed → {e}")

            if correlations and hasattr(self.signal, "update_correlation_context"):
                try:
                    self.signal.update_correlation_context(correlations)
                except Exception as e:
                    print(f"⚠️ [RUNTIME] update_correlation_context failed → {e}")

            return devices

        except Exception as e:
            print(f"⚠️ [RUNTIME] fusion error → {e}")
            return []

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _normalize_identity_result(self, identities: Any) -> List[Dict[str, Any]]:

        if identities is None:
            return []

        if isinstance(identities, list):
            return [item for item in identities if isinstance(item, dict)]

        if isinstance(identities, dict):
            if "identities" in identities and isinstance(identities.get("identities"), list):
                return [item for item in identities["identities"] if isinstance(item, dict)]
            return [identities]

        return []

    def _normalize_fusion_result(self, result: Any) -> List[Dict[str, Any]]:

        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]

        if isinstance(result, dict):
            maybe_devices = result.get("devices", [])
            if isinstance(maybe_devices, list):
                return [item for item in maybe_devices if isinstance(item, dict)]

        return []

    def _propagate_signal_intelligence_to_emitters(
        self,
        emitters: List[Dict[str, Any]],
        signals: List[Dict[str, Any]],
    ) -> None:
        """
        Push signal-level intelligence into emitter objects before fusion.

        Matching is intentionally simple and non-breaking:
        - prefer emitter["signals"] if present
        - otherwise attempt frequency-based carry-over
        """

        if not emitters:
            return

        for emitter in emitters:
            if not isinstance(emitter, dict):
                continue

            emitter_signals = emitter.get("signals") if isinstance(emitter.get("signals"), list) else []
            best_signal = None
            if emitter_signals:
                best_signal = max(
                    (
                        signal for signal in emitter_signals
                        if isinstance(signal, dict)
                    ),
                    key=lambda signal: self._safe_float(signal.get("confidence"), 0.0),
                    default=None,
                )

            # Prefer the first emitter-owned signal that already carries intelligence
            for signal in emitter_signals:
                if not isinstance(signal, dict):
                    continue

                if signal.get("fingerprint") and "fingerprint" not in emitter:
                    emitter["fingerprint"] = signal.get("fingerprint")

                for field in [
                    "vendor",
                    "product",
                    "device_type",
                    "identity_confidence",
                    "fingerprint_confidence",
                ]:
                    if signal.get(field) is not None and emitter.get(field) is None:
                        emitter[field] = signal.get(field)

            if best_signal:
                for field in [
                    "protocol",
                    "rf_protocol",
                    "protocol_confidence",
                    "rf_protocol_confidence",
                    "channel_family",
                    "channel_confidence",
                    "ble_channel",
                    "wifi_channel",
                    "zigbee_channel",
                    "rf_ble_adv_distance_mhz",
                    "rf_burst_periodicity",
                    "rf_duty_cycle",
                    "rf_modulation_hint",
                    "rf_chirp_detected",
                    "rf_frame_structure",
                    "rf_frame_protocol_hint",
                    "rf_frame_confidence",
                    "spectral_chirp_hint",
                    "rf_temporal_profile",
                    "rf_signal_class",
                    "rf_classifier_readiness",
                    "rf_feature_completeness",
                    "rf_observation_count",
                    "rf_identity_continuity_score",
                    "burst_recurrence_score",
                    "signal_type",
                    "bandwidth_estimate_mhz",
                    "bandwidth_class",
                    "temporal_consistency",
                ]:
                    if best_signal.get(field) is not None and emitter.get(field) is None:
                        emitter[field] = best_signal.get(field)

            # Fallback frequency-based carry-over if emitter lacked own signal enrichment
            if emitter_signals:
                continue

            center_freq = self._safe_float(emitter.get("center_freq_mhz"), None)
            if center_freq is None:
                continue

            for signal in signals:
                if not isinstance(signal, dict):
                    continue

                signal_freq = self._safe_float(signal.get("frequency_mhz"), None)
                if signal_freq is None:
                    continue

                if abs(center_freq - signal_freq) <= 2.0:
                    if signal.get("fingerprint") and "fingerprint" not in emitter:
                        emitter["fingerprint"] = signal.get("fingerprint")

                    for field in [
                        "vendor",
                        "product",
                        "device_type",
                        "identity_confidence",
                        "fingerprint_confidence",
                    ]:
                        if signal.get(field) is not None and emitter.get(field) is None:
                            emitter[field] = signal.get(field)
                    break

    def _propagate_emitter_intelligence_to_devices(
        self,
        devices: List[Dict[str, Any]],
        emitters: List[Dict[str, Any]],
    ) -> None:
        """
        Push emitter intelligence into device objects after fusion.

        Matching is intentionally tolerant and additive only.
        """

        if not devices or not emitters:
            return

        for device in devices:
            if not isinstance(device, dict):
                continue

            device_freqs = set()
            for f in device.get("frequencies", []) or []:
                ff = self._safe_float(f, None)
                if ff is not None:
                    device_freqs.add(round(ff, 1))

            for emitter in emitters:
                if not isinstance(emitter, dict):
                    continue

                emitter_freqs = set()
                center = self._safe_float(emitter.get("center_freq_mhz"), None)
                if center is not None:
                    emitter_freqs.add(round(center, 1))

                for signal in emitter.get("signals", []) if isinstance(emitter.get("signals"), list) else []:
                    sf = self._safe_float(signal.get("frequency_mhz"), None)
                    if sf is not None:
                        emitter_freqs.add(round(sf, 1))

                matched = False
                for ef in emitter_freqs:
                    for df in device_freqs:
                        if abs(ef - df) <= 2.0:
                            matched = True
                            break
                    if matched:
                        break

                if not matched and device_freqs:
                    continue

                if emitter.get("fingerprint") is not None and device.get("fingerprint") is None:
                    device["fingerprint"] = emitter.get("fingerprint")

                for field in [
                    "vendor",
                    "product",
                    "device_type",
                    "device_role_hint",
                    "device_role_confidence",
                    "product_category_hint",
                    "product_category_confidence",
                    "behavior_profile_hint",
                    "rf_device_class",
                    "ble_role",
                    "ble_role_confidence",
                    "ble_adv_like",
                    "ble_operating_mode_hint",
                    "zigbee_role",
                    "zigbee_role_confidence",
                    "zigbee_operating_mode_hint",
                    "zigbee_mesh_like",
                    "lora_role",
                    "lora_role_confidence",
                    "lora_operating_mode_hint",
                    "lora_device_type_hint",
                    "lora_device_type_confidence",
                    "lora_network_region",
                    "lora_bandplan",
                    "lora_bandplan_confidence",
                    "lora_cadence_class",
                    "lora_identity_family",
                    "lora_identity_evidence",
                    "lora_mesh_like",
                    "lora_meter_like",
                    "lora_lorawan_like",
                    "lora_mesh_score",
                    "lora_meter_score",
                    "lora_industrial_score",
                    "lora_gateway_score",
                    "lora_dwell_span_mhz",
                    "lora_frequency_count",
                    "subghz_role",
                    "subghz_role_confidence",
                    "subghz_operating_mode_hint",
                    "subghz_profile",
                    "subghz_recurring_like",
                    "subghz_recurrence_confidence",
                    "rf_modulation_hint",
                    "rf_chirp_detected",
                    "rf_frame_structure",
                    "rf_frame_protocol_hint",
                    "rf_frame_confidence",
                    "spectral_chirp_hint",
                    "identity_confidence",
                    "fingerprint_confidence",
                ]:
                    emitter_value = emitter.get(field)
                    if emitter_value is None:
                        continue

                    device_value = device.get(field)

                    if field in {
                        "lora_role_confidence",
                        "lora_device_type_confidence",
                        "lora_bandplan_confidence",
                        "lora_mesh_score",
                        "lora_meter_score",
                        "lora_industrial_score",
                        "lora_gateway_score",
                        "lora_dwell_span_mhz",
                        "lora_frequency_count",
                        "subghz_role_confidence",
                        "subghz_recurrence_confidence",
                        "rf_frame_confidence",
                        "spectral_chirp_hint",
                        "identity_confidence",
                        "fingerprint_confidence",
                    }:
                        if device_value is None or self._safe_float(emitter_value, 0.0) > self._safe_float(device_value, 0.0):
                            device[field] = emitter_value
                        continue

                    if field == "lora_identity_evidence":
                        merged = list(device_value or [])
                        for item in emitter_value if isinstance(emitter_value, list) else [emitter_value]:
                            if item not in merged:
                                merged.append(item)
                        if merged:
                            device[field] = merged
                        continue

                    if field in {
                        "lora_identity_family",
                        "lora_device_type_hint",
                        "lora_network_region",
                        "lora_bandplan",
                        "lora_cadence_class",
                        "lora_role",
                        "lora_operating_mode_hint",
                    }:
                        if device_value is None or (
                            emitter.get("lora_lorawan_like")
                            and not device.get("lora_lorawan_like")
                        ):
                            device[field] = emitter_value
                        continue

                    if device_value is None:
                        device[field] = emitter_value

    def _enrich_devices_if_possible(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        if not devices or self.device_intelligence is None:
            return devices

        methods = ["enrich_devices", "process_devices", "classify_devices", "analyze_devices"]

        for method_name in methods:
            if hasattr(self.device_intelligence, method_name):
                try:
                    enriched = getattr(self.device_intelligence, method_name)(devices)
                    if isinstance(enriched, list):
                        return enriched
                except Exception:
                    pass

        return devices

    def _attach_correlation_context(
        self,
        devices: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]],
    ) -> None:
        if not devices or not correlations:
            return

        by_device_id: Dict[str, Dict[str, Any]] = {}
        for entity in correlations:
            if not isinstance(entity, dict):
                continue
            for device_id in entity.get("device_ids") or []:
                if device_id:
                    by_device_id[str(device_id)] = entity

        for device in devices:
            if not isinstance(device, dict):
                continue
            entity = by_device_id.get(str(device.get("device_id")))
            if not entity:
                continue
            device["correlation_entity_id"] = entity.get("entity_id")
            device["correlation_confidence"] = entity.get("confidence")
            device["correlation_protocols"] = list(entity.get("protocols") or [])
            device["cross_protocol"] = bool(entity.get("cross_protocol"))

    def get_correlation_state(self) -> Dict[str, Any]:
        if not self.correlation_engine:
            return {
                "engine_version": None,
                "entity_count": 0,
                "last_run_ts": 0.0,
                "entities": [],
            }
        return self.correlation_engine.get_state()

    @staticmethod
    def _safe_float(value: Any, default: Optional[float] = 0.0) -> Optional[float]:
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    # =========================================================================
    # STATE
    # =========================================================================
    def get_state(self):

        try:
            sdr = self.sdr.get_state()
            signal = self.signal.get_stats()

            return {
                "runtime_version": self.VERSION,
                "session_active": self.session_controller.is_active(),
                "pipeline_ready": self.session_controller.is_active(),
                "sdr_running": sdr.get("running", False),
                "sdr_healthy": self.sdr.is_healthy(),
                "fft_running": self.fft.is_running(),
                "signal_count": signal.get("active_signals", 0),
                "device_count": len(self.run_device_fusion()),
            }

        except Exception:
            return {"error": "runtime_failed"}


# =============================================================================
# SINGLETON + GETTERS (UNCHANGED)
# =============================================================================
_runtime_instance: Optional[Runtime] = None


def initialize_runtime() -> Runtime:
    global _runtime_instance

    if _runtime_instance:
        return _runtime_instance

    _runtime_instance = Runtime()
    return _runtime_instance


def _require_runtime() -> Runtime:
    if _runtime_instance is None:
        raise RuntimeError("Runtime not initialized")
    return _runtime_instance


def get_runtime() -> Runtime:
    return _require_runtime()


def get_session():
    return _require_runtime().session


def get_session_controller():
    return _require_runtime().session_controller


def get_sdr_controller():
    return _require_runtime().sdr


def get_fft_engine():
    return _require_runtime().fft


def get_signal_engine():
    return _require_runtime().signal


def get_recon_engine():
    return _require_runtime().recon


def get_device_fusion_engine():
    return _require_runtime().device_fusion_engine


def get_tx_controller():
    runtime = _require_runtime()
    if not hasattr(runtime, "tx_controller"):
        raise RuntimeError("TX Controller not initialized")
    return runtime.tx_controller
