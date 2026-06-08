# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/identity_intelligence.py
# VERSION:      v3.2.0 (SIGINT IDENTITY INTELLIGENCE - BLE / MAC / DEVICE INTEL)
# UPDATED:      2026-03-25
# =============================================================================
#
# ARCHITECTURE OVERVIEW
# ---------------------
# This module is the stateful identity persistence layer for GhostRecon.
#
# It sits AFTER:
#   - signal enrichment
#   - device fusion
#   - device intelligence
#   - hardware linking
#
# And BEFORE:
#   - final API exposure
#   - graph / relationship layers
#   - long-term identity persistence and correlation
#
# PRIMARY RESPONSIBILITIES
# ------------------------
# 1. Maintain identity continuity across observation cycles
# 2. Generate stable identity IDs using strongest available anchors
# 3. Track MAC addresses, hardware IDs, fingerprints, vendor/product hypotheses
# 4. Apply OUI-based vendor enrichment for BLE / WiFi style MAC identities
# 5. Detect randomized MAC behavior
# 6. Preserve existing functionality without breaking the current pipeline
#
# DESIGN PRINCIPLES
# -----------------
# - Stateful memory with bounded retention
# - Deterministic identity generation
# - Strongest-anchor identity generation:
#       MAC > hardware_id > fallback feature hash
# - Never remove or overwrite stronger evidence with weaker evidence
# - BLE / WiFi friendly
# - Safe under partial / missing data
# - Thread-safe for runtime pipeline use
#
# IMPORTANT NOTES
# ---------------
# - This file does NOT decode BLE itself.
# - This file does NOT parse packets itself.
# - It enriches already-fused device objects.
# - Randomized MAC detection is heuristic:
#       locally administered bit set => likely randomized/private MAC
# - OUI enrichment only works if the resolver and OUI database are functioning.
#
# =============================================================================

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Dict, Any, List, Optional


# =============================================================================
# OPTIONAL IMPORTS
# =============================================================================
try:
    from backend.intel.identity.mac_oui_resolver import MacOUIResolver
except Exception:
    MacOUIResolver = None

log = logging.getLogger("ghostrecon.identity_intelligence")


class IdentityIntelligence:
    """
    Identity Intelligence Layer (Stateful - SIGINT v3.2.0)

    PURPOSE:
    --------
    Provides persistent identity tracking + enrichment across device observations.

    RESPONSIBILITIES:
    -----------------
    - Identity persistence across cycles
    - Fingerprint continuity
    - Vendor / product stabilization
    - Hardware identity integration
    - MAC/OUI vendor attribution
    - BLE-aware identity generation
    - Randomized MAC detection
    - Confidence boosting using multi-factor signals
    - Prevent identity fragmentation

    DESIGN PRINCIPLES:
    ------------------
    - Stateless input, stateful memory
    - Deterministic identity generation
    - Thread-safe
    - Bounded memory
    - SIGINT-grade extensibility
    - Strongest-identity-anchor first
    """

    VERSION = "3.2.0"

    # -------------------------------------------------------------------------
    # TUNING
    # -------------------------------------------------------------------------
    MAX_IDENTITIES = 5000
    IDENTITY_TTL_SEC = 3600

    CONFIDENCE_BOOST_PER_HIT = 0.05
    MAX_CONFIDENCE_BOOST = 0.30

    HARDWARE_CONFIDENCE_WEIGHT = 0.20
    OUI_CONFIDENCE_WEIGHT = 0.30

    # -------------------------------------------------------------------------
    # INIT
    # -------------------------------------------------------------------------
    def __init__(self):

        self._identities: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        self.oui_resolver = MacOUIResolver() if MacOUIResolver else None

        log.info("[IDENTITY] Initialized | Version=%s", self.VERSION)

    # =========================================================================
    # MAIN PROCESS
    # =========================================================================
    def process(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        if not isinstance(devices, list):
            return devices

        now = time.time()

        with self._lock:
            self._cleanup(now)

            for d in devices:
                if not isinstance(d, dict):
                    continue

                try:
                    self._process_device(d, now)
                except Exception as e:
                    log.debug("[IDENTITY] Device processing error: %s", e)

        return devices

    # =========================================================================
    # DEVICE PROCESSING
    # =========================================================================
    def _process_device(self, d: Dict[str, Any], now: float):

        identity_id = d.get("identity_id")

        # ---------------------------------------------------------------------
        # GENERATE IDENTITY IF MISSING
        # ---------------------------------------------------------------------
        if not identity_id:
            identity_id = self._generate_identity_id(d)
            d["identity_id"] = identity_id

        # ---------------------------------------------------------------------
        # GET / CREATE PROFILE
        # ---------------------------------------------------------------------
        if identity_id not in self._identities:
            self._identities[identity_id] = self._create_profile(d, now)

        profile = self._identities[identity_id]

        # ---------------------------------------------------------------------
        # UPDATE PROFILE
        # ---------------------------------------------------------------------
        profile["last_seen"] = now
        profile["seen_count"] += 1

        # ---------------------------------------------------------------------
        # FINGERPRINT TRACKING
        # ---------------------------------------------------------------------
        fingerprint_id = self._extract_fingerprint_id(d)
        if fingerprint_id:
            profile["fingerprints"].add(fingerprint_id)

        # ---------------------------------------------------------------------
        # HARDWARE TRACKING
        # ---------------------------------------------------------------------
        hw_id = d.get("hardware_id")
        if hw_id:
            profile.setdefault("hardware_ids", set()).add(hw_id)

        # ---------------------------------------------------------------------
        # MAC TRACKING (BLE / WIFI / GENERIC)
        # ---------------------------------------------------------------------
        mac = self._extract_mac_address(d)
        if mac:
            mac = self._normalize_mac(mac)
            if mac:
                profile.setdefault("mac_addresses", set()).add(mac)
                d["mac_address"] = d.get("mac_address") or mac

                if not d.get("identity_source"):
                    d["identity_source"] = "mac_address"

                if self._is_random_mac(mac):
                    d["mac_randomized"] = True
                    profile["mac_randomized"] = True
                else:
                    if "mac_randomized" not in d:
                        d["mac_randomized"] = False

        # ---------------------------------------------------------------------
        # VENDOR / PRODUCT / DEVICE-TYPE STABILIZATION
        # ---------------------------------------------------------------------
        vendor = d.get("vendor")
        if vendor:
            profile["vendor"] = vendor

        product = d.get("product")
        if product:
            profile["product"] = product

        device_type = d.get("device_type")
        if device_type:
            profile["device_type"] = device_type

        device_category = d.get("device_category")
        if device_category:
            profile["device_category"] = device_category

        brand = d.get("brand")
        if brand and not profile.get("vendor"):
            profile["vendor"] = brand

        model = d.get("model")
        if model and not profile.get("product"):
            profile["product"] = model

        # ---------------------------------------------------------------------
        # OUI RESOLUTION
        # ---------------------------------------------------------------------
        self._apply_oui_resolution(d, profile)

        # ---------------------------------------------------------------------
        # APPLY STABILIZED VALUES BACK TO DEVICE
        # ---------------------------------------------------------------------
        d["identity_id"] = identity_id
        d["identity_seen_count"] = profile["seen_count"]
        d["fingerprint_id"] = fingerprint_id
        d["fingerprint_persistence"] = len(profile["fingerprints"])

        if profile.get("hardware_ids"):
            d["hardware_count"] = len(profile["hardware_ids"])

        if profile.get("mac_addresses"):
            d["mac_count"] = len(profile["mac_addresses"])

        if not d.get("vendor") and profile.get("vendor"):
            d["vendor"] = profile["vendor"]

        if not d.get("product") and profile.get("product"):
            d["product"] = profile["product"]

        if not d.get("device_type") and profile.get("device_type"):
            d["device_type"] = profile["device_type"]

        if not d.get("device_category") and profile.get("device_category"):
            d["device_category"] = profile["device_category"]

        if profile.get("mac_randomized"):
            d["mac_randomized"] = True

        # ---------------------------------------------------------------------
        # LIGHTWEIGHT DEVICE-INTEL COHERENCE
        # Keeps existing functionality intact while strengthening BLE identity
        # ---------------------------------------------------------------------
        self._apply_device_intel_hints(d, profile)

        # ---------------------------------------------------------------------
        # CONFIDENCE
        # ---------------------------------------------------------------------
        d["identity_confidence"] = self._compute_confidence(d, profile)

    # =========================================================================
    # DEVICE-INTEL HINTS
    # =========================================================================
    def _apply_device_intel_hints(self, d: Dict[str, Any], profile: Dict[str, Any]):

        # Preserve all existing values first
        device_type = d.get("device_type")
        device_category = d.get("device_category")
        vendor = d.get("vendor") or profile.get("vendor")
        product = d.get("product") or profile.get("product")

        # ---------------------------------------------------------
        # BLE tracker / phone / wearable style hints
        # ---------------------------------------------------------
        service_uuids = d.get("service_uuids") or []
        if not isinstance(service_uuids, list):
            service_uuids = []

        manufacturer_id = d.get("manufacturer_id")
        name = (
            d.get("device_name")
            or d.get("ble_device_name")
            or d.get("local_name")
            or ""
        )
        name_l = str(name).lower()

        # Names
        if not device_type:
            if any(x in name_l for x in ["iphone", "galaxy", "pixel", "phone", "android", "redmi", "oneplus", "oppo", "vivo", "huawei"]):
                d["device_type"] = "phone"
            elif any(x in name_l for x in ["watch", "band", "fitbit", "garmin", "ultra", "wearable"]):
                d["device_type"] = "wearable"
            elif any(x in name_l for x in ["tile", "airtag", "tracker", "smarttag", "chipolo"]):
                d["device_type"] = "tracker"
            elif any(x in name_l for x in ["airpods", "buds", "earbuds", "headphones", "headset"]):
                d["device_type"] = "audio_accessory"
            elif any(x in name_l for x in ["speaker", "soundcore", "jbl", "bose", "sonos"]):
                d["device_type"] = "speaker"
            elif any(x in name_l for x in ["tv", "television", "decoder", "set-top", "stb", "apple tv", "chromecast", "fire tv"]):
                d["device_type"] = "media_device"
            elif any(x in name_l for x in ["bulb", "plug", "switch", "sensor", "camera"]):
                d["device_type"] = "iot_device"

        if not device_category:
            if d.get("device_type") == "phone":
                d["device_category"] = "personal_device"
            elif d.get("device_type") == "wearable":
                d["device_category"] = "wearable"
            elif d.get("device_type") == "tracker":
                d["device_category"] = "tracking_device"
            elif d.get("device_type") == "audio_accessory":
                d["device_category"] = "audio_accessory"
            elif d.get("device_type") == "speaker":
                d["device_category"] = "audio_device"
            elif d.get("device_type") == "media_device":
                d["device_category"] = "consumer_media"
            elif d.get("device_type") == "iot_device":
                d["device_category"] = "iot_device"

        # Known service UUID hints
        normalized_uuids = {str(u).upper() for u in service_uuids}

        if "FEAA" in normalized_uuids:
            d["device_type"] = d.get("device_type") or "beacon"
            d["device_category"] = d.get("device_category") or "beacon"
            d["product"] = d.get("product") or "Eddystone Beacon"

        if "FD6F" in normalized_uuids:
            d["device_type"] = d.get("device_type") or "tracker"
            d["device_category"] = d.get("device_category") or "tracking_device"
            d["product"] = d.get("product") or "Tile"

        # Manufacturer / vendor coherence
        if manufacturer_id and not vendor:
            # Do not overwrite stronger resolved vendor, just leave room for future layers
            d["manufacturer_id"] = manufacturer_id

        # Push stabilized device intel into profile for continuity
        if d.get("device_type"):
            profile["device_type"] = d["device_type"]

        if d.get("device_category"):
            profile["device_category"] = d["device_category"]

        if d.get("vendor"):
            profile["vendor"] = d["vendor"]

        if d.get("product"):
            profile["product"] = d["product"]

    # =========================================================================
    # ID GENERATION
    # =========================================================================
    def _generate_identity_id(self, d: Dict[str, Any]) -> str:

        # ---------------------------------------------------------
        # 1. MAC address (BLE / WiFi / generic radio identity)
        # Strongest identity anchor if present
        # ---------------------------------------------------------
        mac = self._extract_mac_address(d)
        mac = self._normalize_mac(mac)
        if mac:
            clean = mac.replace(":", "").upper()
            prefix = self._identity_prefix_for_device(d)
            return f"{prefix}{clean}"

        # ---------------------------------------------------------
        # 2. Hardware ID
        # ---------------------------------------------------------
        hw = d.get("hardware_id")
        if isinstance(hw, str) and hw.strip():
            return f"ID-HW-{hw.strip()}"

        # ---------------------------------------------------------
        # 3. Existing stabilized feature hash fallback
        # ---------------------------------------------------------
        vendor = str(d.get("vendor", "unknown"))
        product = str(d.get("product", "unknown"))
        device_type = str(d.get("device_type", "unknown"))
        category = str(d.get("device_category", "unknown"))

        protocols = ",".join(sorted(self._safe_list(d.get("protocols"))))
        freqs = ",".join(str(f) for f in self._safe_list(d.get("frequencies")))

        # Preserve previous behavior, but include more identity-relevant fields
        base = f"{vendor}|{product}|{device_type}|{category}|{protocols}|{freqs}"

        return "ID-" + hashlib.sha1(base.encode()).hexdigest()[:12]

    def _identity_prefix_for_device(self, d: Dict[str, Any]) -> str:

        protocols = [str(x).upper() for x in self._safe_list(d.get("protocols"))]
        protocol = str(d.get("protocol", "")).upper()
        rf_protocol = str(d.get("rf_protocol", "")).upper()

        if "BLE" in protocols or "BLUETOOTH" in protocol or "BLUETOOTH" in rf_protocol:
            return "ID-BLE-"

        if "WIFI" in protocols or "802.11" in rf_protocol or "WIFI" in protocol:
            return "ID-WIFI-"

        return "ID-MAC-"

    # =========================================================================
    # OUI RESOLUTION
    # =========================================================================
    def _apply_oui_resolution(self, d: Dict[str, Any], profile: Dict[str, Any]):

        if not self.oui_resolver:
            return

        mac = self._extract_mac_address(d)
        mac = self._normalize_mac(mac)

        if not mac:
            return

        try:
            result = self.oui_resolver.resolve(mac)
        except Exception as e:
            log.debug("[IDENTITY] OUI resolver failure for %s: %s", mac, e)
            return

        if not isinstance(result, dict):
            return

        vendor = result.get("vendor")
        if vendor:
            d["vendor"] = d.get("vendor") or vendor
            d["vendor_confidence"] = result.get("confidence")
            d["oui"] = result.get("oui")
            profile["vendor"] = profile.get("vendor") or vendor

    # =========================================================================
    # PROFILE MANAGEMENT
    # =========================================================================
    def _create_profile(self, d: Dict[str, Any], now: float) -> Dict[str, Any]:

        mac = self._normalize_mac(self._extract_mac_address(d))
        hw = d.get("hardware_id")

        return {
            "identity_id": d.get("identity_id"),
            "first_seen": now,
            "last_seen": now,
            "seen_count": 0,
            "fingerprints": set(),
            "hardware_ids": {hw} if hw else set(),
            "mac_addresses": {mac} if mac else set(),
            "vendor": d.get("vendor"),
            "product": d.get("product"),
            "device_type": d.get("device_type"),
            "device_category": d.get("device_category"),
            "mac_randomized": bool(self._is_random_mac(mac)) if mac else False,
        }

    def _cleanup(self, now: float):

        # Fast path
        if len(self._identities) <= self.MAX_IDENTITIES:
            return

        expired = []

        for k, v in self._identities.items():
            if (now - v.get("last_seen", now)) > self.IDENTITY_TTL_SEC:
                expired.append(k)

        for k in expired:
            self._identities.pop(k, None)

        # If still oversized after TTL cleanup, evict oldest
        if len(self._identities) > self.MAX_IDENTITIES:
            ordered = sorted(
                self._identities.items(),
                key=lambda item: item[1].get("last_seen", 0.0)
            )
            overflow = len(self._identities) - self.MAX_IDENTITIES
            for k, _ in ordered[:overflow]:
                self._identities.pop(k, None)

        if expired:
            log.debug("[IDENTITY] Cleanup removed %d expired identities", len(expired))

    # =========================================================================
    # FINGERPRINT
    # =========================================================================
    def _extract_fingerprint_id(self, d: Dict[str, Any]) -> Optional[str]:

        fp = d.get("fingerprint")

        if isinstance(fp, dict):
            return fp.get("fingerprint_id")

        return None

    # =========================================================================
    # CONFIDENCE MODEL
    # =========================================================================
    def _compute_confidence(self, d: Dict[str, Any], profile: Dict[str, Any]) -> float:

        base = self._safe_float(d.get("identity_confidence"), 0.0)

        # Persistence boost
        persistence = profile.get("seen_count", 0)
        persistence_boost = min(
            self.MAX_CONFIDENCE_BOOST,
            persistence * self.CONFIDENCE_BOOST_PER_HIT
        )

        # Hardware boost
        hw_conf = self._safe_float(d.get("hardware_confidence"), 0.0)
        hw_boost = hw_conf * self.HARDWARE_CONFIDENCE_WEIGHT

        # OUI boost
        oui_conf = self._safe_float(d.get("vendor_confidence"), 0.0)
        oui_boost = oui_conf * self.OUI_CONFIDENCE_WEIGHT

        final = base + persistence_boost + hw_boost + oui_boost

        return round(min(1.0, final), 4)

    # =========================================================================
    # MAC UTILITIES
    # =========================================================================
    def _extract_mac_address(self, d: Dict[str, Any]) -> Optional[str]:

        # Keep backward compatibility with all known fields
        for key in (
            "mac_address",
            "ble_address",
            "wifi_mac",
            "ble_mac",
            "address",
        ):
            value = d.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        return None

    def _normalize_mac(self, mac: Optional[str]) -> Optional[str]:

        if not isinstance(mac, str):
            return None

        mac = mac.strip().replace("-", ":").upper()
        parts = mac.split(":")

        if len(parts) == 6 and all(len(p) in (1, 2) for p in parts):
            try:
                parts = [f"{int(p, 16):02X}" for p in parts]
                return ":".join(parts)
            except Exception:
                return None

        # Support raw 12-hex MAC without separators
        compact = mac.replace(":", "")
        if len(compact) == 12:
            try:
                int(compact, 16)
                return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
            except Exception:
                return None

        return None

    # =========================================================================
    # RANDOM MAC DETECTION
    # =========================================================================
    def _is_random_mac(self, mac: Optional[str]) -> bool:
        try:
            mac = self._normalize_mac(mac)
            if not mac:
                return False

            first_byte = int(mac.split(":")[0], 16)

            # Locally administered bit set => private/randomized style address
            return bool(first_byte & 0b00000010)
        except Exception:
            return False

    # =========================================================================
    # HELPERS
    # =========================================================================
    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    @staticmethod
    def _safe_list(value):
        if isinstance(value, list):
            return value
        return []
