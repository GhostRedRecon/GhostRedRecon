# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/recon/fingerprinting/unified_fingerprint_engine.py
# VERSION:      v2.0.0 (SIGINT FINGERPRINT INTELLIGENCE ENGINE)
# UPDATED:      2026-03-24
# =============================================================================

from typing import Dict, Any, List, Optional


class UnifiedFingerprintEngine:
    """
    SIGINT-grade unified fingerprint engine

    Combines:
    - Protocol fingerprinting
    - Hardware fingerprinting
    - Behavior fingerprinting

    Produces:
    - Normalized fingerprint
    - Vendor inference
    - Device classification
    - Confidence scoring

    CRITICAL:
    - Writes directly into signal (Phase 4 requirement)
    """

    VERSION = "2.0.0"

    def __init__(
        self,
        protocol_engine=None,
        hardware_engine=None,
        behavior_engine=None,
    ):
        self.protocol_engine = protocol_engine
        self.hardware_engine = hardware_engine
        self.behavior_engine = behavior_engine

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def process(self, signals: List[Dict[str, Any]]):

        if not signals:
            return

        for signal in signals:
            try:
                fingerprint = self._build_fingerprint(signal)

                if not fingerprint:
                    continue

                # -----------------------------------------------------------------
                # 🔥 CRITICAL: Inject fingerprint
                # -----------------------------------------------------------------
                signal["fingerprint"] = fingerprint
                signal["fingerprint_confidence"] = fingerprint.get("confidence", 0.0)

                # -----------------------------------------------------------------
                # 🔥 PROPAGATE TO TOP LEVEL (VALIDATOR NEEDS THIS)
                # -----------------------------------------------------------------
                self._propagate_to_signal(signal, fingerprint)

            except Exception:
                continue

    # =========================================================================
    # BUILD FINGERPRINT
    # =========================================================================
    def _build_fingerprint(self, signal: Dict[str, Any]) -> Optional[Dict[str, Any]]:

        proto = self._safe_process(self.protocol_engine, signal)
        hw = self._safe_process(self.hardware_engine, signal)
        beh = self._safe_process(self.behavior_engine, signal)

        if not any([proto, hw, beh]):
            return None

        vendor = self._infer_vendor(signal, proto, hw)
        device_type = self._infer_device_type(signal, proto, beh)

        confidence = self._compute_confidence(proto, hw, beh)

        return {
            "protocol": proto or {},
            "hardware": hw or {},
            "behavior": beh or {},
            "vendor": vendor,
            "device_type": device_type,
            "confidence": confidence,
        }

    # =========================================================================
    # SAFE ENGINE EXECUTION
    # =========================================================================
    def _safe_process(self, engine, signal):

        if engine is None or not hasattr(engine, "process"):
            return None

        try:
            result = engine.process([signal])

            if isinstance(result, list) and result:
                return result[0]

            if isinstance(result, dict):
                return result

            return signal.get("fingerprint_partial")

        except Exception:
            return None

    # =========================================================================
    # VENDOR INFERENCE (NEW)
    # =========================================================================
    def _infer_vendor(self, signal, proto, hw):

        # BLE OUI / identity hint
        if signal.get("ble_device_id"):
            oui = signal.get("ble_device_id")[:8]

            if oui.startswith("F4:"):
                return "Apple"
            if oui.startswith("DC:"):
                return "Samsung"

        # Hardware fingerprint
        if isinstance(hw, dict):
            if hw.get("vendor"):
                return hw.get("vendor")

        # Protocol-based heuristic
        if proto:
            p = proto.get("protocol")

            if p == "BLE":
                return "Generic BLE Device"
            if p == "WIFI":
                return "WiFi Device"

        return None

    # =========================================================================
    # DEVICE TYPE INFERENCE (NEW)
    # =========================================================================
    def _infer_device_type(self, signal, proto, beh):

        if beh and isinstance(beh, dict):
            if beh.get("pattern") == "beacon":
                return "Beacon"
            if beh.get("pattern") == "periodic":
                return "IoT Sensor"

        if proto:
            p = proto.get("protocol")

            if p == "BLE":
                return "BLE Device"
            if p == "WIFI":
                return "WiFi Client"

        return None

    # =========================================================================
    # CONFIDENCE MODEL (UPGRADED)
    # =========================================================================
    def _compute_confidence(self, proto, hw, beh):

        score = 0.0

        if proto:
            score += 0.5

        if hw:
            score += 0.3

        if beh:
            score += 0.2

        return round(min(1.0, score), 3)

    # =========================================================================
    # PROPAGATION (CRITICAL FOR PHASE 4)
    # =========================================================================
    def _propagate_to_signal(self, signal, fingerprint):

        if not fingerprint:
            return

        # Vendor
        if fingerprint.get("vendor"):
            signal["vendor"] = fingerprint["vendor"]

        # Device type
        if fingerprint.get("device_type"):
            signal["device_type"] = fingerprint["device_type"]

        # Protocol
        proto = fingerprint.get("protocol", {})
        if proto.get("protocol"):
            signal["rf_protocol"] = proto.get("protocol")
