from __future__ import annotations

from typing import Any, Dict, List

from backend.intel.identity.device_identity_extractor import DeviceIdentityExtractor
from backend.intel.identity.identity_enrichment_layer import IdentityEnrichmentLayer


class RFIdentityResolver:
    """
    Runtime-facing identity resolver for live signal objects.

    This resolver is intentionally lightweight and non-destructive:
    - enriches signals with hardware fingerprint hints
    - extracts stable identity anchors when available
    - preserves stronger existing values
    """

    VERSION = "1.0.0"

    def __init__(self) -> None:
        self.extractor = DeviceIdentityExtractor()
        self.enrichment = IdentityEnrichmentLayer()

    def process(self, signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not isinstance(signals, list):
            return []

        try:
            self.enrichment.process(signals)
        except Exception:
            pass

        for signal in signals:
            if not isinstance(signal, dict):
                continue
            try:
                identity = self.extractor.extract(signal)
                self._merge_identity(signal, identity)
            except Exception:
                continue

        return signals

    def _merge_identity(self, signal: Dict[str, Any], identity: Dict[str, Any]) -> None:
        if not identity:
            return

        primary_id = identity.get("primary_id")
        identity_source = identity.get("identity_source")
        fingerprint_id = identity.get("fingerprint_id")
        vendor = identity.get("vendor")
        vendor_oui = identity.get("vendor_oui")
        identity_type = identity.get("identity_type")
        confidence = identity.get("confidence")
        evidence = identity.get("evidence") or []
        secondary = identity.get("secondary_id") or {}

        if primary_id and not signal.get("identity_id"):
            signal["identity_id"] = primary_id

        if fingerprint_id and not signal.get("fingerprint_id"):
            signal["fingerprint_id"] = fingerprint_id

        if identity_source and not signal.get("identity_source"):
            signal["identity_source"] = identity_source

        if identity_type and not signal.get("identity_type"):
            signal["identity_type"] = identity_type

        if confidence is not None:
            existing = signal.get("identity_confidence")
            if existing is None or float(confidence) > float(existing):
                signal["identity_confidence"] = confidence

        if vendor and not signal.get("vendor"):
            signal["vendor"] = vendor
        elif vendor_oui and not signal.get("vendor"):
            signal["vendor"] = vendor_oui

        if vendor_oui and not signal.get("vendor_oui"):
            signal["vendor_oui"] = vendor_oui

        if evidence:
            current = signal.get("identity_evidence") or []
            merged = list(dict.fromkeys([*current, *evidence]))
            signal["identity_evidence"] = merged

        if secondary:
            if secondary.get("name") and not signal.get("device_name"):
                signal["device_name"] = secondary["name"]
            if secondary.get("uuid") and not signal.get("uuid"):
                signal["uuid"] = secondary["uuid"]
            if secondary.get("ssid") and not signal.get("ssid"):
                signal["ssid"] = secondary["ssid"]
