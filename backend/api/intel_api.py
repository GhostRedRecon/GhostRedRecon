# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/api/intel_api.py
# VERSION:      v14.0.0 (BLE INTELLIGENCE INTEGRATION)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations

import time
from typing import Any, Dict, List

from fastapi import APIRouter, Query, Request
from backend.integrations.sdr_tab_sweep_manager import SDRTabSweepManager

# 🔥 EXISTING OPTIONAL IMPORTS
try:
    from backend.intel.rf_normalizer import normalize_rf
    from backend.intel.rf_matcher import match_yaml
    from backend.intel.rf_db_loader import load_yaml_db
except Exception:
    normalize_rf = None
    match_yaml = None
    load_yaml_db = None

# 🔥 EXISTING: IDENTITY INTELLIGENCE
try:
    from backend.intel.identity.identity_intelligence import IdentityIntelligence
except Exception as e:
    print(f"[INTEL_API] IdentityIntelligence import failed: {e}")
    IdentityIntelligence = None

# 🔥 EXISTING: IDENTITY ENRICHMENT
try:
    from backend.intel.identity.identity_enrichment_layer import IdentityEnrichmentLayer
except Exception as e:
    print(f"[INTEL_API] IdentityEnrichmentLayer import failed: {e}")
    IdentityEnrichmentLayer = None

# 🔥 EXISTING: DEVICE HARDWARE LINKER
try:
    from backend.intel.identity.device_hardware_linker import DeviceHardwareLinker
except Exception as e:
    print(f"[INTEL_API] DeviceHardwareLinker import failed: {e}")
    DeviceHardwareLinker = None

# 🔥 NEW: BLE DECODER WORKER
try:
    from backend.intel.ble.ble_decoder_worker import BLEDecoderWorker
except Exception as e:
    print(f"[INTEL_API] BLEDecoderWorker import failed: {e}")
    BLEDecoderWorker = None

try:
    from backend.intel.lora.lora_lab_profile_matcher import LoRaLabProfileMatcher
except Exception as e:
    print(f"[INTEL_API] LoRaLabProfileMatcher import failed: {e}")
    LoRaLabProfileMatcher = None

try:
    from backend.intel.lora.lora_decoder_worker import LoRaDecoderWorker
except Exception as e:
    print(f"[INTEL_API] LoRaDecoderWorker import failed: {e}")
    LoRaDecoderWorker = None

router = APIRouter(prefix="/api/intel", tags=["intel"])


# =============================================================================
# GLOBAL ENGINES (STATEFUL — IMPORTANT)
# =============================================================================
_identity_intel = IdentityIntelligence() if IdentityIntelligence else None
_identity_enrichment = IdentityEnrichmentLayer() if IdentityEnrichmentLayer else None
_device_hw_linker = DeviceHardwareLinker() if DeviceHardwareLinker else None
_lora_lab_matcher = LoRaLabProfileMatcher() if LoRaLabProfileMatcher else None
_lora_decoder_worker = LoRaDecoderWorker() if LoRaDecoderWorker else None

# 🔥 BLE ENGINE (ON-DEMAND)
_ble_worker = BLEDecoderWorker() if BLEDecoderWorker else None
_sdr_sweep_manager = SDRTabSweepManager()


# =============================================================================
# HELPERS
# =============================================================================
def _get_runtime(request: Request):
    return getattr(request.app.state, "runtime", None)


def _safe_call(obj: Any, method_name: str, *args, **kwargs):
    try:
        if obj and hasattr(obj, method_name):
            return getattr(obj, method_name)(*args, **kwargs)
    except Exception:
        return None


def _safe_int(v, default=0):
    try:
        return int(v)
    except:
        return default


def _safe_float(v, default=0.0):
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


_BAND_CONFIDENCE_MINIMUMS = {
    "sub-ghz": 0.42,
    "ble": 0.38,
    "lora": 0.5,
    "zigbee": 0.45,
    "wifi": 0.58,
    "iot": 0.32,
}


def _freq_family_bucket(freq_mhz: Any) -> str:
    freq = _safe_float(freq_mhz, 0.0)
    if freq <= 0:
        return "unknown"
    if freq < 1000:
        if 860 <= freq <= 930:
            return "subghz_lora"
        return "subghz"
    if 2400 <= freq <= 2485:
        if abs(freq - 2402.0) <= 3 or abs(freq - 2426.0) <= 3 or abs(freq - 2480.0) <= 3:
            return "ble"
        if 2403 <= freq <= 2483:
            return "zigbee_or_wifi"
        return "wifi"
    if 5000 <= freq <= 6000:
        return "wifi"
    return "wideband"


def _record_confidence(record: Dict[str, Any]) -> float:
    return max(
        _safe_float(record.get("confidence")),
        _safe_float(record.get("signal_confidence")),
        _safe_float(record.get("protocol_confidence")),
        _safe_float(record.get("rf_protocol_confidence")),
        _safe_float(record.get("channel_confidence")),
        _safe_float(record.get("device_confidence")),
    )


def _record_has_explicit_conflict(record: Dict[str, Any], family: str) -> bool:
    family = str(family or "").lower()
    fields = [
        record.get("protocol"),
        record.get("rf_protocol"),
        record.get("channel_family"),
        record.get("device_type"),
        record.get("device_category"),
        record.get("rf_device_class"),
        record.get("vendor"),
        record.get("product_category_hint"),
    ]
    text = " ".join(str(value or "").lower() for value in fields)
    conflicts = {
        "subghz": ("wifi", "bluetooth", "ble", "zigbee", "802.15.4"),
        "lora": ("wifi", "bluetooth", "ble", "zigbee", "802.15.4"),
        "ble": ("wifi", "zigbee", "802.15.4", "lora", "lorawan"),
        "zigbee": ("wifi", "bluetooth", "ble", "lora", "lorawan"),
        "wifi": ("bluetooth", "ble", "zigbee", "802.15.4", "lora", "lorawan"),
    }
    return any(token in text for token in conflicts.get(family, ()))


def _family_frequency_compatible(record: Dict[str, Any], band: str) -> bool:
    family = _record_family(record)
    freq_value = record.get("frequency_mhz") or record.get("freq_mhz")
    if freq_value is None and isinstance(record.get("frequencies"), list) and record.get("frequencies"):
        freq_value = record.get("frequencies")[0]
    bucket = _freq_family_bucket(freq_value)
    target = str(band or "").strip().lower()
    if target == "sub-ghz":
        return family in {"subghz", "lora"} and bucket in {"subghz", "subghz_lora"}
    if target == "lora":
        return family == "lora" and bucket in {"subghz", "subghz_lora"}
    if target == "ble":
        return family == "ble" and bucket == "ble"
    if target == "zigbee":
        return family == "zigbee" and bucket in {"zigbee_or_wifi", "ble"}
    if target == "wifi":
        return family == "wifi" and bucket in {"zigbee_or_wifi", "wifi"}
    return True


def _record_matches_band_strict(record: Dict[str, Any], band: str) -> bool:
    target = str(band or "").strip().lower()
    if target == "iot":
        return _is_iot_signal(record)
    if not _record_matches_band(record, target):
        return False
    if not _family_frequency_compatible(record, target):
        return False
    family = _record_family(record)
    if family and _record_has_explicit_conflict(record, family):
        return False
    if _record_confidence(record) < _BAND_CONFIDENCE_MINIMUMS.get(target, 0.0):
        return False
    if target == "wifi":
        protocol = str(record.get("protocol") or "").upper()
        rf_protocol = str(record.get("rf_protocol") or "").upper()
        channel_family = str(record.get("channel_family") or "").lower()
        if not (
            protocol == "WIFI"
            or "802.11" in rf_protocol
            or channel_family == "wifi"
            or record.get("wifi_channel") is not None
        ):
            return False
    if target == "sub-ghz":
        freq = _safe_float(record.get("frequency_mhz") or record.get("freq_mhz"))
        if freq >= 1000:
            return False
    return True


def _tab_band_capability(band: str, runtime: Any) -> Dict[str, Any]:
    band_lower = str(band or "").strip().lower()
    hackrf_available = bool(getattr(runtime, "sdr", None))
    base = {
        "band": str(band or "").upper(),
        "state": "ready",
        "production_ready": True,
        "can_sweep": hackrf_available,
        "reason": "",
        "detail": "",
    }
    if not hackrf_available:
        base.update({
            "state": "unavailable",
            "production_ready": False,
            "can_sweep": False,
            "reason": "HackRF runtime is unavailable.",
            "detail": "The SDR runtime is not initialized on this backend.",
        })
        return base

    if band_lower == "ble":
        status = _get_ble_decoder_status()
        live_backend_available = any(bool(entry.get("available")) and entry.get("mode") == "live_sdr" for entry in status.get("available_backends") or [])
        if not live_backend_available:
            base.update({
                "state": "degraded",
                "production_ready": False,
                "can_sweep": False,
                "reason": "No live BLE decoder backend is available.",
                "detail": status.get("last_error") or "Install GNU Radio/osmosdr or btle_rx before presenting BLE as operator-ready.",
            })
        return base

    if band_lower == "lora":
        base.update({
            "state": "degraded",
            "production_ready": False,
            "can_sweep": False,
            "reason": "LoRa live decode is not integrated into the operator pipeline.",
            "detail": "The current LoRa path is profile-only and does not provide a verified live decoder workflow.",
        })
        return base

    return base


def _ensure_ble_worker_running(runtime: Any = None) -> None:
    if not _ble_worker:
        return
    if runtime is not None and hasattr(_ble_worker, "bind_runtime"):
        try:
            _ble_worker.bind_runtime(runtime)
        except Exception:
            pass
    if _ble_worker.running:
        return
    try:
        _ble_worker.start()
    except Exception:
        pass


def _stop_ble_worker() -> None:
    if not _ble_worker or not _ble_worker.running:
        return
    try:
        _ble_worker.stop()
    except Exception:
        pass


_IOT_PROTOCOL_HINTS = {
    "ble",
    "bluetooth_le",
    "zigbee",
    "ieee_802.15.4",
    "ieee_802.15.4_zigbee",
    "ieee_802154_zigbee",
    "thread",
    "lora",
    "lorawan",
    "wireless_mbus",
    "wmbus",
    "proprietary_iot",
    "subghz_fsk",
    "subghz_ook",
}

_IOT_TEXT_HINTS = {
    "iot",
    "ikea",
    "tradfri",
    "dirigera",
    "styrbar",
    "rodret",
    "parasoll",
    "vallhorn",
    "badring",
    "fyrtur",
    "tretakt",
    "sensor",
    "meter",
    "telemetry",
    "tracker",
    "beacon",
    "phone",
    "smartphone",
    "wearable",
    "watch",
    "earbuds",
    "headphones",
    "gateway",
    "hub",
    "camera",
    "plug",
    "bulb",
    "thermostat",
    "alarm",
    "lock",
    "appliance",
    "leak",
    "flow",
    "parking",
    "utility",
    "mesh",
    "smarthome",
    "smart home",
    "speaker",
    "tv",
    "decoder",
    "set-top",
    "apple",
    "samsung",
    "google",
    "jbl",
    "bose",
    "orange",
    "end device",
}

_IOT_WIFI_HINTS = {
    "camera",
    "plug",
    "bulb",
    "thermostat",
    "vacuum",
    "speaker",
    "doorbell",
    "robot",
    "appliance",
    "printer",
    "iot",
    "sensor",
}

_FAMILY_DISALLOWED_TEXT = {
    "ble": {
        "wifi",
        "access point",
        "ssid",
        "wlan",
        "wifi_device",
        "zigbee",
        "802.15.4",
        "zigbee_sensor",
        "zigbee_iot",
        "lora",
        "lorawan",
        "meshtastic",
    },
    "zigbee": {
        "wifi",
        "access point",
        "ssid",
        "wlan",
        "wifi_device",
        "ble",
        "bluetooth",
        "tracker tag",
        "asset_tracker",
        "beacon",
        "lora",
        "lorawan",
        "meshtastic",
    },
    "wifi": {
        "zigbee",
        "802.15.4",
        "zigbee_sensor",
        "zigbee_iot",
        "ble",
        "bluetooth",
        "tracker tag",
        "asset_tracker",
        "beacon",
        "lora",
        "lorawan",
        "meshtastic",
    },
}

_FOREIGN_FAMILY_FIELDS = {
    "ble": [
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
        "subghz_role",
        "subghz_role_confidence",
        "subghz_operating_mode_hint",
        "subghz_profile",
    ],
    "zigbee": [
        "ble_role",
        "ble_role_confidence",
        "ble_adv_like",
        "ble_operating_mode_hint",
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
        "subghz_role",
        "subghz_role_confidence",
        "subghz_operating_mode_hint",
        "subghz_profile",
    ],
    "wifi": [
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
        "subghz_role",
        "subghz_role_confidence",
        "subghz_operating_mode_hint",
        "subghz_profile",
    ],
}


def _build_text_haystack(record: Dict[str, Any], keys: List[str]) -> str:
    return " ".join(str(record.get(key, "") or "") for key in keys).lower()


def _is_iot_signal(signal: Dict[str, Any]) -> bool:
    protocol = str(signal.get("protocol") or "").lower()
    rf_protocol = str(signal.get("rf_protocol") or "").lower()
    channel_family = str(signal.get("channel_family") or "").lower()
    device_text = _build_text_haystack(
        signal,
        [
            "device",
            "device_class",
            "device_type",
            "device_category",
            "rf_band",
            "vendor",
            "rf_device_class",
            "behavior_profile_hint",
            "product_category_hint",
            "lora_device_type_hint",
            "subghz_profile",
        ],
    )
    protocols = {protocol, rf_protocol, channel_family}

    if protocols & _IOT_PROTOCOL_HINTS:
        if protocol == "wifi" or channel_family == "wifi" or "802.11" in rf_protocol:
            return any(hint in device_text for hint in _IOT_WIFI_HINTS)
        return True

    if any(hint in device_text for hint in _IOT_TEXT_HINTS):
        return True

    try:
        freq = float(signal.get("frequency_mhz") or signal.get("freq_mhz") or 0.0)
    except Exception:
        freq = 0.0

    if freq < 1000 and any(tag in device_text for tag in {"meter", "telemetry", "utility", "sensor"}):
        return True

    return False


def _is_iot_device(device: Dict[str, Any]) -> bool:
    protocols = _normalize_protocol_labels(device.get("protocols") or [])
    text = str(device).lower()

    if protocols & {"BLE", "ZIGBEE", "THREAD", "LORA", "WIRELESS_MBUS", "PROPRIETARY_IOT"}:
        return True

    if "WIFI" in protocols and any(hint in text for hint in _IOT_WIFI_HINTS):
        return True

    if "SUBGHZ_FSK" in protocols or "SUBGHZ_OOK" in protocols:
        if any(hint in text for hint in {"meter", "telemetry", "utility", "sensor", "alarm", "iot"}):
            return True

    return any(hint in text for hint in _IOT_TEXT_HINTS)


def _get_iot_profile_inventory(runtime) -> List[Dict[str, Any]]:
    engine = getattr(runtime, "device_intelligence", None)
    if engine is None:
        return []

    families = {"wifi", "bluetooth_le", "zigbee", "thread", "wireless_mbus", "proprietary_iot", "lora", "subghz_fsk", "subghz_ook"}
    inventory = []
    seen = set()

    for collection_name in ("device_profiles", "product_profiles"):
        for profile in getattr(engine, collection_name, []) or []:
            if not isinstance(profile, dict):
                continue
            family = str(profile.get("protocol_family") or "").lower()
            if family not in families:
                continue
            name = str(profile.get("product_name") or profile.get("device") or "").strip()
            if not name:
                continue
            key = (collection_name, name.lower())
            if key in seen:
                continue
            seen.add(key)
            inventory.append(
                {
                    "profile_name": name,
                    "profile_type": "product" if collection_name == "product_profiles" else "device",
                    "vendor": profile.get("vendor"),
                    "device": profile.get("device"),
                    "category": profile.get("category"),
                    "protocol_family": profile.get("protocol_family"),
                    "protocol_subtypes": profile.get("protocol_subtypes") or [],
                    "expected_band_mhz": profile.get("expected_band_mhz") or [],
                }
            )
    return inventory


def _filter_signals_for_band(signals: List[Dict[str, Any]], band: str) -> List[Dict[str, Any]]:
    band = (band or "").strip().lower()
    if not band:
        return signals

    return [
        signal
        for signal in signals
        if isinstance(signal, dict) and _record_matches_band_strict(signal, band)
    ]


def _top_counts(items: List[Dict[str, Any]], key_fn, limit: int = 6) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for item in items:
        key = key_fn(item)
        if not key:
            continue
        counts[str(key)] = counts.get(str(key), 0) + 1
    return [
        {"label": label, "count": count}
        for label, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    ]


def _normalize_protocol_labels(values: List[Any]) -> set[str]:
    normalized = set()
    for value in values:
        label = str(value or "").upper().replace("-", "_")
        if not label:
            continue
        if label == "BLUETOOTH_LE":
            normalized.add("BLE")
            continue
        normalized.add(label)
    return normalized


def _record_family(record: Dict[str, Any]) -> str:
    protocols = _normalize_protocol_labels(
        [
            record.get("protocol"),
            record.get("rf_protocol"),
            *list(record.get("protocols") or []),
        ]
    )
    channel_family = str(record.get("channel_family") or "").lower()

    if channel_family in {"ble", "zigbee", "wifi", "thread"}:
        return channel_family
    if "BLE" in protocols or record.get("ble_role") or record.get("ble_adv_like") or record.get("mac_address"):
        return "ble"
    if "ZIGBEE" in protocols or record.get("zigbee_role") or record.get("zigbee_channel") is not None:
        return "zigbee"
    if "WIFI" in protocols or record.get("wifi_channel") is not None:
        return "wifi"
    if "LORA" in protocols or record.get("lora_identity_family") or record.get("lora_bandplan"):
        return "lora"
    if protocols & {"SUBGHZ_FSK", "SUBGHZ_OOK"} or record.get("subghz_role") or record.get("subghz_profile"):
        return "subghz"
    return channel_family or ""


def _compatible_families(left: str, right: str) -> bool:
    if not left or not right:
        return True
    return left == right


def _record_matches_band(record: Dict[str, Any], band: str) -> bool:
    family = _record_family(record)
    target = str(band or "").strip().lower()
    if not target:
        return True
    if target == "ble":
        return family == "ble"
    if target == "zigbee":
        return family == "zigbee"
    if target == "wifi":
        return family == "wifi"
    if target == "lora":
        return family == "lora"
    if target == "sub-ghz":
        return family in {"lora", "subghz"}
    if target == "iot":
        return _is_iot_device(record)
    return True


def _has_conflicting_family_text(value: Any, family: str) -> bool:
    haystack = str(value or "").strip().lower()
    if not haystack or family not in _FAMILY_DISALLOWED_TEXT:
        return False
    return any(token in haystack for token in _FAMILY_DISALLOWED_TEXT[family])


def _sanitize_family_identity(record: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(record, dict):
        return record

    family = _record_family(record)
    if family not in {"ble", "zigbee", "wifi"}:
        return record

    for field in _FOREIGN_FAMILY_FIELDS.get(family, []):
        record.pop(field, None)

    for field in (
        "product",
        "device_type",
        "device_category",
        "product_category_hint",
        "matched_product_profile",
        "matched_device_profile",
        "matched_burst_signature",
    ):
        if _has_conflicting_family_text(record.get(field), family):
            record[field] = None

    if family == "ble":
        if record.get("ble_role") and not record.get("device_type"):
            record["device_type"] = "BLE Device"
        if not record.get("device_category") and record.get("ble_role"):
            record["device_category"] = "ble_device"
        if record.get("product_category_hint") and _has_conflicting_family_text(record.get("product_category_hint"), family):
            record["product_category_hint"] = None
    elif family == "zigbee":
        if record.get("zigbee_role") and not record.get("device_type"):
            record["device_type"] = "Zigbee Device"
        if record.get("zigbee_role") and record.get("device_category") is None:
            record["device_category"] = "zigbee_device"
        if record.get("zigbee_role") and record.get("product_category_hint") is None:
            record["product_category_hint"] = "zigbee_sensor"
    elif family == "wifi":
        if record.get("wifi_channel") is not None and not record.get("device_type"):
            record["device_type"] = "WiFi Device"
        if record.get("device_category") is None:
            record["device_category"] = "wifi_device"
        if _has_conflicting_family_text(record.get("product_category_hint"), family):
            record["product_category_hint"] = None

    return record


def _decoder_support(record: Dict[str, Any]) -> Dict[str, Any]:
    protocols = _normalize_protocol_labels(
        [
            record.get("protocol"),
            record.get("rf_protocol"),
            *list(record.get("protocols") or []),
        ]
    )
    return {
        "ble_decoder_backed": bool(_ble_worker) and "BLE" in protocols,
        "lora_profile_matcher": bool(_lora_lab_matcher) and "LORA" in protocols,
        "identity_enrichment": bool(_identity_enrichment),
        "device_intelligence": True,
    }


def _ble_decoded_evidence_score(record: Dict[str, Any]) -> float:
    score = 0.0
    if record.get("mac_address"):
        score += 0.28
    if record.get("manufacturer_id"):
        score += 0.26
    if record.get("device_name"):
        score += 0.24
    if record.get("service_uuids"):
        score += 0.18
    if record.get("service_data"):
        score += 0.16
    if record.get("appearance") is not None:
        score += 0.10
    if record.get("ble_payload"):
        score += 0.10
    return max(0.0, min(score, 1.0))


def _apply_ble_precision_guard(record: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(record, dict) or _record_family(record) != "ble":
        return record
    decoded_score = _ble_decoded_evidence_score(record)
    record["ble_decoded_evidence_score"] = round(decoded_score, 4)
    record["ble_identity_basis"] = "decoded" if decoded_score >= 0.45 else "rf_only"
    if decoded_score >= 0.45:
        return record

    for field in (
        "product",
        "product_category_hint",
        "matched_product_profile",
        "matched_device_profile",
        "matched_burst_signature",
        "probable_product_family",
    ):
        record[field] = None
    if not record.get("manufacturer_confirmed"):
        record["vendor"] = None
        record["probable_vendor_family"] = None
    if not record.get("device_type"):
        record["device_type"] = "BLE Device"
    if not record.get("device_category"):
        record["device_category"] = "ble_device"
    record["rf_device_class"] = "ble_unknown"
    return record


def _build_signal_evidence(signal: Dict[str, Any]) -> Dict[str, Any]:
    confidence = _safe_float(signal.get("confidence"), 0.0)
    protocol = str(signal.get("protocol") or "")
    vendor = signal.get("vendor") or signal.get("rf_vendor_candidate")
    device_hint = signal.get("device_type") or signal.get("device_category") or signal.get("rf_device_class")
    flags = {
        "signal_detected": True,
        "protocol_inferred": bool(protocol and protocol != "UNKNOWN_PROTOCOL"),
        "device_hint_present": bool(device_hint),
        "vendor_hint_present": bool(vendor),
        "profile_match_present": bool(signal.get("lora_lab_profile_name")),
        "decoder_backed": bool(signal.get("mac_address") or signal.get("rf_frame_protocol_hint") or signal.get("ble_payload")),
    }
    if _record_family(signal) == "ble" and _ble_decoded_evidence_score(signal) >= 0.45:
        tier = "identity_supported"
    elif flags["decoder_backed"] or flags["profile_match_present"] or flags["vendor_hint_present"]:
        tier = "identity_supported"
    elif flags["device_hint_present"]:
        tier = "device_inferred"
    elif flags["protocol_inferred"]:
        tier = "protocol_inferred"
    else:
        tier = "signal_detected"
    return {
        "evidence_tier": tier,
        "evidence_flags": flags,
        "confidence_tier": "high" if confidence >= 0.8 else ("medium" if confidence >= 0.5 else "low"),
        "decoder_support": _decoder_support(signal),
        "data_freshness_sec": _safe_float(time.time() - _safe_float(signal.get("last_seen"), time.time()), 0.0),
    }


def _build_device_evidence(device: Dict[str, Any]) -> Dict[str, Any]:
    confidence = _safe_float(device.get("confidence"), 0.0)
    vendor = device.get("vendor")
    product = device.get("product")
    flags = {
        "signal_detected": bool(device.get("frequencies")),
        "protocol_inferred": bool(_normalize_protocol_labels(device.get("protocols") or [])),
        "device_hint_present": bool(device.get("device_type") or device.get("device_category") or device.get("lora_identity_family")),
        "vendor_hint_present": bool(vendor),
        "product_hint_present": bool(product),
        "profile_match_present": bool(device.get("lora_lab_profile_name") or device.get("matched_product_profile") or device.get("matched_device_profile")),
        "decoder_backed": bool(device.get("mac_address") or device.get("ble_payload")),
    }
    if _record_family(device) == "ble" and _ble_decoded_evidence_score(device) >= 0.45:
        tier = "identity_supported"
    elif flags["decoder_backed"] or flags["product_hint_present"] or flags["profile_match_present"]:
        tier = "identity_supported"
    elif flags["vendor_hint_present"] or flags["device_hint_present"]:
        tier = "device_inferred"
    elif flags["protocol_inferred"]:
        tier = "protocol_inferred"
    else:
        tier = "signal_detected"
    return {
        "evidence_tier": tier,
        "evidence_flags": flags,
        "confidence_tier": "high" if confidence >= 0.8 else ("medium" if confidence >= 0.5 else "low"),
        "decoder_support": _decoder_support(device),
        "data_freshness_sec": _safe_float(time.time() - _safe_float(device.get("last_seen"), time.time()), 0.0),
    }


def _get_ble_decoder_status() -> Dict[str, Any]:
    if not _ble_worker:
        return {
            "running": False,
            "backend_id": None,
            "available_backends": [],
            "last_error": "BLE decoder worker unavailable",
        }
    try:
        status = _ble_worker.get_status()
        recent_events = _ble_worker.get_recent_events(limit=120)
        unique_macs = {
            str(event.get("mac_address") or "")
            for event in recent_events
            if event.get("mac_address")
        }
        spam_events = [event for event in recent_events if bool(event.get("spam_like"))]
        randomized_events = [
            event for event in recent_events
            if str(event.get("privacy_state") or "").lower() == "randomized"
        ]
        spam_snapshots = []
        try:
            spam_snapshots = [
                snapshot
                for snapshot in _ble_worker.get_device_snapshot(limit=120, trusted_only=False)
                if bool(snapshot.get("spam_like"))
            ]
        except Exception:
            spam_snapshots = []
        pdu_counts: Dict[str, int] = {}
        manufacturer_ids: set[str] = set()
        service_uuids: set[str] = set()
        for event in recent_events:
            label = str(event.get("pdu_type_label") or "UNKNOWN")
            pdu_counts[label] = pdu_counts.get(label, 0) + 1
            manufacturer_id = str(event.get("manufacturer_id") or "").upper()
            if manufacturer_id:
                manufacturer_ids.add(manufacturer_id)
            for uuid in (event.get("service_uuids") or []):
                if uuid:
                    service_uuids.add(str(uuid).upper())
        recent_count = len(recent_events)
        spam_event_count = max(len(spam_events), len(spam_snapshots))
        spam_ratio = (spam_event_count / recent_count) if recent_count else 0.0
        randomized_ratio = (len(randomized_events) / recent_count) if recent_count else 0.0
        scan_rsp_ratio = (pdu_counts.get("SCAN_RSP", 0) / recent_count) if recent_count else 0.0
        nonconn_ratio = (pdu_counts.get("ADV_NONCONN_IND", 0) / recent_count) if recent_count else 0.0
        decoder_alert = "none"
        decoder_alert_confidence = 0.0
        probable_tool_class = None
        spam_profiles: List[Dict[str, Any]] = []
        nonconnectable_flood = (
            recent_count >= 40
            and len(unique_macs) >= 30
            and nonconn_ratio >= 0.65
            and (spam_ratio >= 0.25 or randomized_ratio >= 0.45)
        )
        if (
            (recent_count >= 8 and len(unique_macs) >= 6 and spam_ratio >= 0.5)
            or nonconnectable_flood
        ):
            decoder_alert = "BLE spam swarm detected"
            decoder_alert_confidence = min(
                0.97,
                0.42
                + spam_ratio * 0.22
                + randomized_ratio * 0.14
                + nonconn_ratio * 0.16
                + min(0.12, len(unique_macs) * 0.003),
            )
        if "FE2C" in service_uuids and randomized_ratio >= 0.45:
            spam_profiles.append({
                "label": "Android Fast Pair spam posture",
                "confidence": round(min(0.93, 0.62 + randomized_ratio * 0.18 + scan_rsp_ratio * 0.12), 3),
            })
        if "004C" in manufacturer_ids and randomized_ratio >= 0.45:
            spam_profiles.append({
                "label": "Apple popup / Continuity spam posture",
                "confidence": round(min(0.93, 0.58 + randomized_ratio * 0.22 + scan_rsp_ratio * 0.08), 3),
            })
        if "FEAA" in service_uuids:
            spam_profiles.append({
                "label": "Beacon spoof spam posture",
                "confidence": 0.79,
            })
        if decoder_alert != "none" and (
            (randomized_ratio >= 0.6 and (scan_rsp_ratio >= 0.1 or len(spam_profiles) >= 1))
            or nonconnectable_flood
        ):
            probable_tool_class = "Possible Flipper Zero BLE Spam"
        if decoder_alert != "none" and len(spam_profiles) >= 2:
            spam_profiles.append({
                "label": "Kitchen sink / multi-profile BLE spam posture",
                "confidence": round(min(0.96, 0.72 + min(0.14, len(spam_profiles) * 0.05)), 3),
            })
        status["spam_summary"] = {
            "recent_event_count": recent_count,
            "recent_unique_mac_count": len(unique_macs),
            "spam_event_count": spam_event_count,
            "spam_event_ratio": round(spam_ratio, 3),
            "randomized_event_ratio": round(randomized_ratio, 3),
            "scan_response_ratio": round(scan_rsp_ratio, 3),
            "nonconnectable_ratio": round(nonconn_ratio, 3),
            "pdu_counts": pdu_counts,
            "manufacturer_ids": sorted(manufacturer_ids),
            "service_uuids": sorted(service_uuids),
            "spam_profiles": sorted(spam_profiles, key=lambda item: float(item.get("confidence") or 0.0), reverse=True),
            "alert": decoder_alert,
            "alert_confidence": round(decoder_alert_confidence, 3),
            "probable_tool_class": probable_tool_class,
        }
        return status
    except Exception as exc:
        return {
            "running": False,
            "backend_id": None,
            "available_backends": [],
            "last_error": str(exc),
        }


def _get_ble_capture_profile(freq_mhz: float | None = None) -> Dict[str, Any]:
    if not _ble_worker or not hasattr(_ble_worker, "recommend_capture_profile"):
        return {}
    try:
        return _ble_worker.recommend_capture_profile(freq_mhz)
    except Exception:
        return {}


def _match_devices_for_signals(signals: List[Dict[str, Any]], devices: List[Dict[str, Any]], band: str = "") -> List[Dict[str, Any]]:
    if not signals or not devices:
        return []

    vendors = {
        str(s.get("vendor") or s.get("rf_vendor_candidate") or "").lower()
        for s in signals
        if s.get("vendor") or s.get("rf_vendor_candidate")
    }
    freqs = []
    for signal in signals:
        try:
            freqs.append(float(signal.get("frequency_mhz") or signal.get("freq_mhz")))
        except Exception:
            continue
    signal_protocols = _normalize_protocol_labels([
        *(signal.get("protocol") for signal in signals),
        *(signal.get("rf_protocol") for signal in signals),
    ])
    signal_family = _record_family(signals[0]) if signals else ""

    matched = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        device_family = _record_family(device)
        if not _compatible_families(signal_family, device_family):
            continue
        if band and not _record_matches_band(device, band):
            continue
        device_protocols = _normalize_protocol_labels(device.get("protocols") or [])
        explicit_non_ble = {
            proto for proto in device_protocols
            if proto not in {"BLE", "UNKNOWN_PROTOCOL"}
        }
        if "BLE" in signal_protocols and explicit_non_ble and "BLE" not in device_protocols:
            continue
        explicit_non_zigbee = {
            proto for proto in device_protocols
            if proto not in {"ZIGBEE", "UNKNOWN_PROTOCOL"}
        }
        if "ZIGBEE" in signal_protocols and explicit_non_zigbee and "ZIGBEE" not in device_protocols:
            continue
        haystack = str(device).lower()
        vendor_match = any(v and v in haystack for v in vendors)
        freq_match = False
        for device_freq in device.get("frequencies") or []:
            try:
                df = float(device_freq)
            except Exception:
                continue
            if any(abs(df - sf) <= 1.0 for sf in freqs):
                freq_match = True
                break
        if vendor_match or freq_match:
            matched.append(device)
    return matched


def _extract_band_indicators(band: str, signals: List[Dict[str, Any]], devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    band_lower = band.lower()
    frequencies = []
    for signal in signals:
        try:
            frequencies.append(float(signal.get("frequency_mhz") or signal.get("freq_mhz")))
        except Exception:
            continue

    common = {
        "signal_count": len(signals),
        "matched_device_count": len(devices),
        "protocol_density": _top_counts(signals, lambda s: s.get("protocol") or s.get("rf_protocol") or "UNKNOWN"),
        "vendor_density": _top_counts(signals, lambda s: s.get("vendor") or s.get("rf_vendor_candidate") or "UNKNOWN"),
        "active_frequencies": sorted({round(freq, 3) for freq in frequencies})[:20],
    }

    if band_lower == "sub-ghz":
        recurring = [
            {
                "signal_id": s.get("signal_id"),
                "frequency_mhz": s.get("frequency_mhz"),
                "hit_count": s.get("hit_count"),
                "periodicity": s.get("periodicity"),
                "burst_ratio": s.get("burst_ratio"),
            }
            for s in signals
            if _safe_int(s.get("hit_count")) >= 3 or s.get("periodicity") is not None
        ]
        common["burst_recurrence"] = recurring[:10]
        common["class_posture"] = _top_counts(signals, lambda s: s.get("device") or s.get("device_class") or s.get("rf_device_class"))
        return common

    if band_lower == "ble":
        ble_identities = []
        decoder_status = _get_ble_decoder_status()
        recent_events: List[Dict[str, Any]] = []
        if _ble_worker:
            recent_events = _ble_worker.get_recent_events(limit=120)
            ble_snapshots = _ble_worker.get_device_snapshot(limit=40, trusted_only=False)
            for meta in ble_snapshots:
                timeline = [
                    {
                        "timestamp": event.get("timestamp"),
                        "channel": event.get("channel"),
                        "frequency": event.get("frequency"),
                        "rssi": event.get("rssi"),
                        "device_name": event.get("device_name"),
                    }
                    for event in recent_events
                    if event.get("mac_address") == meta.get("mac_address")
                ][-8:]
                ble_identities.append(
                    {
                        "mac_address": meta.get("mac_address"),
                        "seen_count": meta.get("seen_count"),
                        "first_seen": meta.get("first_seen"),
                        "last_seen": meta.get("last_seen"),
                        "device_name": meta.get("device_name"),
                        "device_hint": meta.get("device_hint"),
                        "probable_vendor_family": meta.get("probable_vendor_family"),
                        "probable_product_family": meta.get("probable_product_family"),
                        "best_confidence": meta.get("best_confidence"),
                        "best_evidence_score": meta.get("best_evidence_score"),
                        "latest_evidence_score": meta.get("latest_evidence_score"),
                        "evidence_quality": meta.get("evidence_quality"),
                        "evidence_reasons": meta.get("evidence_reasons"),
                        "trusted_identity": meta.get("trusted_identity"),
                        "trust_reasons": meta.get("trust_reasons"),
                        "paired_scan_response": meta.get("paired_scan_response"),
                        "paired_scan_response_count": meta.get("paired_scan_response_count"),
                        "ad_structure_count": meta.get("ad_structure_count"),
                        "manufacturer_data_present": meta.get("manufacturer_data_present"),
                        "service_hint_count": meta.get("service_hint_count"),
                        "scan_response_seen_count": meta.get("scan_response_seen_count"),
                        "privacy_state": meta.get("privacy_state"),
                        "address_rotation_count": meta.get("address_rotation_count"),
                        "observed_pdu_types": meta.get("observed_pdu_types"),
                        "extended_advertising_seen": meta.get("extended_advertising_seen"),
                        "tracker_like": meta.get("tracker_like"),
                        "beacon_like": meta.get("beacon_like"),
                        "apple_findmy_like": meta.get("apple_findmy_like"),
                        "appearance_label": meta.get("appearance_label"),
                        "service_uuid_names": meta.get("service_uuid_names"),
                        "channels": meta.get("channels"),
                        "last_frequency_mhz": meta.get("last_frequency_mhz"),
                        "last_rssi": meta.get("last_rssi"),
                        "spam_like": meta.get("spam_like"),
                        "spam_confidence": meta.get("spam_confidence"),
                        "spam_reasons": meta.get("spam_reasons"),
                        "timeline": timeline,
                    }
                )
            common["trusted_identity_count"] = len([
                identity for identity in ble_identities
                if identity.get("trusted_identity")
            ])
        attack_leads: List[Dict[str, Any]] = []
        ble_signals = [signal for signal in signals if _record_family(signal) == "ble"]
        flood_signals = [
            signal for signal in ble_signals
            if str(signal.get("ble_role") or "").lower() == "ble_advertising_flood"
            or "flood" in str(signal.get("ble_operating_mode_hint") or "").lower()
            or bool(signal.get("spam_like"))
        ]
        rf_only_signals = [
            signal for signal in ble_signals
            if str(signal.get("ble_identity_basis") or "rf_only").lower() == "rf_only"
            or _safe_float(signal.get("ble_decoded_evidence_score")) < 0.45
        ]
        randomized_identities = [
            device for device in devices
            if _record_family(device) == "ble" and str(device.get("privacy_state") or "").lower() == "randomized"
        ]
        frequency_span = 0.0
        if frequencies:
            try:
                frequency_span = round(max(frequencies) - min(frequencies), 3)
            except Exception:
                frequency_span = 0.0
        packet_count = _safe_int(decoder_status.get("packet_count"))
        empty_capture_count = _safe_int(decoder_status.get("empty_capture_count"))
        unique_frequency_count = len({round(freq, 3) for freq in frequencies})
        flood_ratio = (len(flood_signals) / len(ble_signals)) if ble_signals else 0.0
        rf_only_ratio = (len(rf_only_signals) / len(ble_signals)) if ble_signals else 0.0
        randomized_ratio = (len(randomized_identities) / len(devices)) if devices else 0.0
        event_count = len(recent_events)
        event_randomized_count = sum(1 for event in recent_events if str(event.get("privacy_state") or "").lower() == "randomized")
        event_public_count = sum(1 for event in recent_events if str(event.get("privacy_state") or "").lower() == "public")
        unique_recent_macs = len({str(event.get("mac_address") or "") for event in recent_events if event.get("mac_address")})
        pdu_counts: Dict[str, int] = {}
        manufacturer_ids: set[str] = set()
        service_uuids: set[str] = set()
        for event in recent_events:
            pdu_label = str(event.get("pdu_type_label") or "UNKNOWN")
            pdu_counts[pdu_label] = pdu_counts.get(pdu_label, 0) + 1
            manufacturer_id = str(event.get("manufacturer_id") or "").upper()
            if manufacturer_id:
                manufacturer_ids.add(manufacturer_id)
            for uuid in (event.get("service_uuids") or []):
                if uuid:
                    service_uuids.add(str(uuid).upper())
        scan_rsp_ratio = (pdu_counts.get("SCAN_RSP", 0) / event_count) if event_count else 0.0
        nonconn_ratio = (pdu_counts.get("ADV_NONCONN_IND", 0) / event_count) if event_count else 0.0
        randomized_event_ratio = (event_randomized_count / event_count) if event_count else 0.0
        now_ts = time.time()
        last_event_age_sec = (
            max(0.0, now_ts - _safe_float(decoder_status.get("last_event_at"), now_ts))
            if decoder_status.get("last_event_at")
            else float("inf")
        )
        decoder_recent = last_event_age_sec <= 20.0
        spam_event_count = _safe_int((decoder_status.get("spam_summary") or {}).get("spam_event_count"))
        spam_event_ratio = _safe_float((decoder_status.get("spam_summary") or {}).get("spam_event_ratio"))
        scan_rsp_ratio_summary = _safe_float((decoder_status.get("spam_summary") or {}).get("scan_response_ratio"))
        strong_decoder_spam = (
            decoder_recent
            and event_count >= 24
            and unique_recent_macs >= 12
            and (
                randomized_event_ratio >= 0.55
                or spam_event_count >= 12
                or spam_event_ratio >= 0.35
                or (nonconn_ratio >= 0.65 and unique_recent_macs >= 30)
            )
        )
        strong_rf_flood = (
            len(flood_signals) >= 10
            and unique_frequency_count >= 3
            and rf_only_ratio >= 0.9
        )
        strong_randomized_identity_swarm = (
            len(randomized_identities) >= 8
            and randomized_ratio >= 0.65
        )
        branded_spam_detected = decoder_recent and (
            "FE2C" in service_uuids
            or ("004C" in manufacturer_ids and randomized_event_ratio >= 0.5)
            or "FEAA" in service_uuids
        )
        verified_ble_spam = (
            decoder_recent
            and (
                strong_decoder_spam
                or (unique_recent_macs >= 10 and (randomized_event_ratio >= 0.6 or spam_event_count >= 10))
                or (spam_event_count >= 14 and scan_rsp_ratio_summary >= 0.15)
                or (unique_recent_macs >= 30 and nonconn_ratio >= 0.65 and spam_event_ratio >= 0.25)
                or branded_spam_detected
            )
        )
        verified_ble_flood_attack = verified_ble_spam and (
            strong_rf_flood or strong_randomized_identity_swarm
        )

        attack_verdict = "none"
        attack_confidence = 0.0
        probable_tool_class = None
        tool_class_confidence = 0.0
        attack_classes: List[Dict[str, Any]] = []
        if verified_ble_flood_attack:
            attack_leads.append({
                "label": "BLE advertising flood detected",
                "count": len(flood_signals),
                "severity": "high" if len(flood_signals) >= 6 else "medium",
                "detail": f"{len(flood_signals)} flood-like signals across {unique_frequency_count} active frequencies",
            })
        if verified_ble_spam:
            attack_leads.append({
                "label": "High randomized advertiser churn",
                "count": max(len(randomized_identities), unique_recent_macs),
                "severity": "high" if max(len(randomized_identities), unique_recent_macs) >= 12 else "medium",
                "detail": (
                    f"{unique_recent_macs} recent advertisers, randomized event ratio {(randomized_event_ratio * 100):.0f}%"
                    if decoder_recent
                    else f"{len(randomized_identities)} randomized identities observed"
                ),
            })
        if strong_rf_flood and not verified_ble_spam:
            attack_leads.append({
                "label": "RF posture is suspicious but decoder evidence is not verified",
                "count": unique_frequency_count,
                "severity": "medium",
                "detail": (
                    f"Decoder last event {last_event_age_sec:.0f}s ago"
                    if decoder_recent is False
                    else f"{unique_recent_macs} decoded advertisers observed, below attack threshold"
                ),
            })
        if verified_ble_flood_attack and rf_only_ratio >= 0.9:
            attack_leads.append({
                "label": "Possible BLE spam / synthetic advertiser source",
                "count": max(len(flood_signals), len(randomized_identities)),
                "severity": "high",
                "detail": f"RF-only BLE ratio {(rf_only_ratio * 100):.0f}%",
            })
        if verified_ble_flood_attack:
            attack_verdict = "BLE flood attack detected"
            attack_confidence = min(
                0.98,
                0.34
                + min(0.28, flood_ratio * 0.28)
                + min(0.18, rf_only_ratio * 0.18)
                + (0.10 if decoder_recent else 0.0)
                + (0.08 if unique_recent_macs >= 12 else 0.0),
            )
        if (
            verified_ble_spam
            and unique_frequency_count >= 3
            and (rf_only_ratio >= 0.7 or spam_event_ratio >= 0.35)
            and decoder_recent
            and unique_recent_macs >= 12
            and (
                randomized_event_ratio >= 0.55
                or spam_event_count >= 12
                or (nonconn_ratio >= 0.65 and unique_recent_macs >= 30)
            )
        ):
            probable_tool_class = "Possible Flipper Zero BLE Spam"
            tool_class_confidence = min(
                0.92,
                0.48
                + min(0.18, flood_ratio * 0.18)
                + min(0.16, max(rf_only_ratio, spam_event_ratio) * 0.16)
                + (0.08 if unique_frequency_count >= 3 else 0.0)
                + (0.08 if scan_rsp_ratio_summary >= 0.15 else 0.0),
            )
        if verified_ble_spam and unique_recent_macs >= 10 and randomized_event_ratio >= 0.6:
            attack_classes.append({
                "label": "Synthetic rotating advertiser swarm",
                "confidence": round(min(0.95, 0.45 + randomized_event_ratio * 0.3 + min(0.2, unique_recent_macs * 0.02)), 3),
                "detail": f"{unique_recent_macs} recent advertisers, randomized event ratio {(randomized_event_ratio * 100):.0f}%",
            })
        if verified_ble_spam and unique_recent_macs >= 30 and nonconn_ratio >= 0.65:
            attack_classes.append({
                "label": "Non-connectable advertiser flood",
                "confidence": round(min(0.96, 0.54 + nonconn_ratio * 0.24 + min(0.16, unique_recent_macs * 0.003)), 3),
                "detail": f"ADV_NONCONN_IND ratio {(nonconn_ratio * 100):.0f}% across {event_count} recent packets",
            })
        if verified_ble_spam and (scan_rsp_ratio >= 0.2 or pdu_counts.get("SCAN_RSP", 0) >= 4):
            attack_classes.append({
                "label": "Pairing-abuse posture",
                "confidence": round(min(0.88, 0.36 + scan_rsp_ratio * 0.7), 3),
                "detail": f"SCAN_RSP ratio {(scan_rsp_ratio * 100):.0f}% across {event_count} recent packets",
            })
        if decoder_recent and "FE2C" in service_uuids:
            attack_classes.append({
                "label": "Android Fast Pair spam detected",
                "confidence": 0.83,
                "detail": "Recent BLE packets exposed Fast Pair service UUID FE2C",
            })
        if decoder_recent and "004C" in manufacturer_ids and randomized_event_ratio >= 0.5:
            attack_classes.append({
                "label": "Apple popup / Continuity spam detected",
                "confidence": round(min(0.9, 0.52 + randomized_event_ratio * 0.3), 3),
                "detail": "Apple manufacturer observations mixed with randomized advertiser churn",
            })
        if decoder_recent and any(bool(identity.get("tracker_like")) or bool(identity.get("apple_findmy_like")) for identity in ble_identities):
            attack_classes.append({
                "label": "Tracker spoof posture",
                "confidence": 0.74,
                "detail": "Tracker-like BLE identity traits observed in advertiser set",
            })
        if decoder_recent and "FEAA" in service_uuids:
            attack_classes.append({
                "label": "Beacon spoof spam detected",
                "confidence": 0.78,
                "detail": "Eddystone/FEAA beacon signatures observed in recent BLE packets",
            })
        if decoder_recent and len({
            "FE2C" if "FE2C" in service_uuids else None,
            "004C" if "004C" in manufacturer_ids else None,
            "FEAA" if "FEAA" in service_uuids else None,
        } - {None}) >= 2:
            attack_classes.append({
                "label": "Kitchen sink / multi-profile BLE spam detected",
                "confidence": round(min(0.97, 0.74 + min(0.12, randomized_event_ratio * 0.12)), 3),
                "detail": "Multiple branded BLE spam signatures were observed in the same recent event window",
            })
        attack_classes = sorted(attack_classes, key=lambda item: float(item.get("confidence") or 0.0), reverse=True)
        top_attack_class = attack_classes[0]["label"] if attack_classes else None
        if top_attack_class and attack_verdict != "none":
            attack_verdict = top_attack_class
            attack_confidence = max(
                attack_confidence,
                float(attack_classes[0].get("confidence") or 0.0),
            )
        common["advertiser_identities"] = ble_identities
        common["decoder_status"] = decoder_status
        common["channel_posture"] = _top_counts(signals, lambda s: s.get("channel") or s.get("ble_channel") or s.get("metadata", {}).get("channel"))
        common["identity_correlation"] = len([d for d in devices if d.get("mac_address")])
        common["attack_leads"] = attack_leads
        common["attack_metrics"] = {
            "flood_signal_count": len(flood_signals),
            "flood_signal_ratio": round(flood_ratio, 3),
            "rf_only_signal_count": len(rf_only_signals),
            "rf_only_signal_ratio": round(rf_only_ratio, 3),
            "randomized_identity_count": len(randomized_identities),
            "randomized_identity_ratio": round(randomized_ratio, 3),
            "unique_frequency_count": unique_frequency_count,
            "frequency_span_mhz": frequency_span,
            "decoder_packet_count": packet_count,
            "decoder_empty_capture_count": empty_capture_count,
            "recent_event_count": event_count,
            "recent_unique_mac_count": unique_recent_macs,
            "recent_randomized_event_ratio": round(randomized_event_ratio, 3),
            "recent_scan_response_ratio": round(scan_rsp_ratio, 3),
            "recent_public_event_count": event_public_count,
            "decoder_recent": decoder_recent,
            "decoder_last_event_age_sec": round(last_event_age_sec, 3) if last_event_age_sec != float("inf") else None,
        }
        common["attack_verdict"] = {
            "label": attack_verdict,
            "confidence": round(attack_confidence, 3),
            "probable_tool_class": probable_tool_class,
            "tool_class_confidence": round(tool_class_confidence, 3) if probable_tool_class else 0.0,
        }
        common["attack_classes"] = attack_classes
        return common

    if band_lower == "zigbee":
        common["channel_posture"] = _top_counts(signals, lambda s: s.get("channel") or s.get("zigbee_channel"))
        common["mesh_nodes"] = _top_counts(devices, lambda d: d.get("device_id") or d.get("device_type"))
        common["mesh_protocols"] = _top_counts(signals, lambda s: s.get("protocol") or s.get("rf_protocol"))
        return common

    if band_lower == "lora":
        role_counts = {"gateway": 0, "end_device": 0, "unknown": 0}
        for signal in signals:
            haystack = str(signal).lower()
            if "gateway" in haystack:
                role_counts["gateway"] += 1
            elif "sensor" in haystack or "device" in haystack or "node" in haystack:
                role_counts["end_device"] += 1
            else:
                role_counts["unknown"] += 1
        matched_profile_devices = [device for device in devices if device.get("lora_lab_profile_name")]
        common["role_posture"] = role_counts
        common["frequency_clusters"] = _top_counts(signals, lambda s: f"{round(float(s.get('frequency_mhz') or s.get('freq_mhz') or 0.0), 1)} MHz")
        common["matched_lab_profile_count"] = len(matched_profile_devices)
        common["matched_lab_profiles"] = _top_counts(matched_profile_devices, lambda d: d.get("lora_lab_profile_name"))
        common["matched_lab_vendors"] = _top_counts(matched_profile_devices, lambda d: d.get("vendor"))
        common["bandplan_density"] = _top_counts(devices, lambda d: d.get("lora_bandplan") or "unknown")
        return common

    if band_lower == "wifi":
        common["channel_posture"] = _top_counts(signals, lambda s: s.get("wifi_channel") or s.get("channel"))
        coexistence = 0
        for signal in signals:
            haystack = str(signal).lower()
            if "ble" in haystack or "zigbee" in haystack:
                coexistence += 1
        common["adjacent_band_pressure"] = coexistence
        common["coexistence_vendors"] = _top_counts(signals, lambda s: s.get("vendor") or s.get("rf_vendor_candidate"))
        return common

    if band_lower == "iot":
        iot_devices = [device for device in devices if _is_iot_device(device)]
        multi_protocol_devices = []
        for device in iot_devices:
            protocols = device.get("protocols") or []
            if isinstance(protocols, list) and len(protocols) > 1:
                multi_protocol_devices.append(
                    {
                        "device_id": device.get("device_id"),
                        "protocols": protocols,
                        "vendor": device.get("vendor"),
                        "device_type": device.get("device_type"),
                    }
                )
        common["cross_protocol_entities"] = multi_protocol_devices[:10]
        common["protocol_overlap"] = _top_counts(signals, lambda s: s.get("protocol") or s.get("rf_protocol"))
        common["family_density"] = _top_counts(
            iot_devices,
            lambda d: (
                d.get("lora_identity_family")
                or d.get("device_category")
                or d.get("device_type")
                or d.get("rf_device_class")
            ),
        )
        common["matched_profile_density"] = _top_counts(
            iot_devices,
            lambda d: d.get("matched_product_profile") or d.get("matched_device_profile") or d.get("matched_burst_signature"),
        )
        common["utility_density"] = _top_counts(
            iot_devices,
            lambda d: (
                d.get("device_type")
                if any(token in str(d).lower() for token in {"meter", "utility", "wireless m-bus", "wmbus"})
                else None
            ),
        )
        common["role_density"] = _top_counts(
            iot_devices,
            lambda d: (
                d.get("device_role_hint")
                or d.get("ble_role")
                or d.get("zigbee_role")
                or d.get("lora_role")
                or d.get("subghz_role")
            ),
        )
        common["sub_band_density"] = [
            {"label": "2.4 GHz", "count": sum(1 for s in signals if _safe_float(s.get("frequency_mhz") or s.get("freq_mhz")) >= 2400)},
            {"label": "Sub-GHz", "count": sum(1 for s in signals if 0 < _safe_float(s.get("frequency_mhz") or s.get("freq_mhz")) < 1000)},
        ]
        common["capture_recommendations"] = [
            "Prioritize BLE advertising channels 37/38/39 for discovery density.",
            "Sample Zigbee channels 11/15/20/25 before full 2.4 GHz mesh sweeps.",
            "Keep WiFi IoT checks narrow on channels 1/6/11 instead of broad WiFi scans.",
            "For EU telemetry, anchor 433.92 / 868.30 / 868.95 / 869.525 MHz before broad Sub-GHz sweeps.",
        ]
        return common

    return common


# =============================================================================
# 🔥 CENTRALIZED SIGNAL ENRICHMENT (UNCHANGED)
# =============================================================================
def _get_enriched_signals(runtime, limit=500, active_only=False, sort_by="priority_score"):

    signal_engine = getattr(runtime, "signal", None)
    raw = _safe_call(
        signal_engine,
        "get_top_signals",
        limit,
        False,
        active_only,
        sort_by,
    ) or []

    if not isinstance(raw, list):
        return []

    if _identity_enrichment:
        try:
            raw = _identity_enrichment.process(raw)
        except Exception as e:
            print("[INTEL_API] Identity enrichment failed:", e)

    enriched = []
    for signal in raw:
        if not isinstance(signal, dict):
            continue
        signal_copy = dict(signal)
        _sanitize_family_identity(signal_copy)
        _apply_ble_precision_guard(signal_copy)
        signal_copy.update(_build_signal_evidence(signal_copy))
        enriched.append(signal_copy)
    return enriched


# =============================================================================
# 🔥 INTELLIGENCE EXTRACTION (UNCHANGED)
# =============================================================================
def _extract_intelligence(device: Dict[str, Any]):

    identity = {
        "identity_present": bool(device.get("identity_id")),
        "vendor": device.get("vendor"),
        "product": device.get("product"),
        "identity_confidence": device.get("confidence", 0.0),
    }

    fingerprint = device.get("fingerprint") or {}

    intel = device.get("intelligence", {})

    if isinstance(intel, dict) and intel:
        identity_summary = intel.get("identity_summary", {})
        fingerprint_summary = intel.get("fingerprint_summary", {})

        key = device.get("identity_id") or device.get("device_id")

        if key in identity_summary:
            identity = identity_summary[key]

        if key in fingerprint_summary:
            fingerprint = fingerprint_summary[key]

    return identity, fingerprint


# =============================================================================
# DEVICE NORMALIZATION (UNCHANGED)
# =============================================================================
def _format_device(d: Dict[str, Any]) -> Dict[str, Any]:

    if not isinstance(d, dict):
        return {}

    device_copy = dict(d)
    _sanitize_family_identity(device_copy)
    _apply_ble_precision_guard(device_copy)

    identity, fingerprint = _extract_intelligence(device_copy)
    resolved_vendor = (
        identity.get("vendor")
        or device_copy.get("manufacturer_company")
        or device_copy.get("probable_vendor_family")
        or device_copy.get("vendor")
    )
    resolved_product = (
        identity.get("product")
        or device_copy.get("probable_product_family")
        or device_copy.get("product")
    )
    vendor_source = "identity_summary" if identity.get("vendor") else (
        "manufacturer_company" if device_copy.get("manufacturer_company") else (
            "signature_or_family" if device_copy.get("probable_vendor_family") else (
                "device_vendor" if device_copy.get("vendor") else None
            )
        )
    )
    vendor_confidence = (
        identity.get("identity_confidence")
        if identity.get("vendor")
        else (0.9 if device_copy.get("manufacturer_company") else (0.72 if device_copy.get("probable_vendor_family") else (0.6 if device_copy.get("vendor") else 0.0)))
    )

    payload = {
        "device_id": device_copy.get("device_id"),
        "protocols": list(device_copy.get("protocols", [])),
        "frequencies": list(device_copy.get("frequencies", [])),
        "rf_bands": list(device_copy.get("rf_bands", [])),
        "confidence": device_copy.get("confidence"),
        "last_seen": device_copy.get("last_seen"),

        "vendor": resolved_vendor,
        "product": resolved_product,
        "vendor_confidence": max(float(device_copy.get("vendor_confidence") or 0.0), float(vendor_confidence or 0.0)),
        "vendor_source": device_copy.get("vendor_source") or vendor_source,
        "manufacturer_company": device_copy.get("manufacturer_company"),
        "manufacturer_confirmed": device_copy.get("manufacturer_confirmed"),
        "probable_vendor_family": device_copy.get("probable_vendor_family"),

        "identity_id": device_copy.get("identity_id"),
        "identity_confidence": identity.get("identity_confidence"),

        "fingerprint": fingerprint,
        "fingerprint_strength": fingerprint.get("fingerprint_strength"),
        "identity_status": device_copy.get("identity_status"),
        "matched_device_profile": device_copy.get("matched_device_profile"),
        "matched_product_profile": device_copy.get("matched_product_profile"),
        "matched_burst_signature": device_copy.get("matched_burst_signature"),

        "device_type": device_copy.get("device_type"),
        "device_category": device_copy.get("device_category"),
        "device_role_hint": device_copy.get("device_role_hint"),
        "device_role_confidence": device_copy.get("device_role_confidence"),
        "product_category_hint": device_copy.get("product_category_hint"),
        "product_category_confidence": device_copy.get("product_category_confidence"),
        "behavior_profile_hint": device_copy.get("behavior_profile_hint"),
        "rf_device_class": device_copy.get("rf_device_class"),
        "ble_role": device_copy.get("ble_role"),
        "ble_role_confidence": device_copy.get("ble_role_confidence"),
        "ble_adv_like": device_copy.get("ble_adv_like"),
        "ble_operating_mode_hint": device_copy.get("ble_operating_mode_hint"),
        "ble_decoded_evidence_score": device_copy.get("ble_decoded_evidence_score"),
        "ble_identity_basis": device_copy.get("ble_identity_basis"),
        "trusted_identity": device_copy.get("trusted_identity"),
        "trust_reasons": device_copy.get("trust_reasons"),
        "trust_score": device_copy.get("trust_score"),
        "privacy_state": device_copy.get("privacy_state"),
        "best_evidence_score": device_copy.get("best_evidence_score"),
        "paired_scan_response": device_copy.get("paired_scan_response"),
        "paired_scan_response_count": device_copy.get("paired_scan_response_count"),
        "scan_response_seen_count": device_copy.get("scan_response_seen_count"),
        "crc_valid_count": device_copy.get("crc_valid_count"),
        "lora_role": device_copy.get("lora_role"),
        "lora_role_confidence": device_copy.get("lora_role_confidence"),
        "lora_operating_mode_hint": device_copy.get("lora_operating_mode_hint"),
        "lora_device_type_hint": device_copy.get("lora_device_type_hint"),
        "lora_device_type_confidence": device_copy.get("lora_device_type_confidence"),
        "lora_network_region": device_copy.get("lora_network_region"),
        "lora_bandplan": device_copy.get("lora_bandplan"),
        "lora_bandplan_confidence": device_copy.get("lora_bandplan_confidence"),
        "lora_cadence_class": device_copy.get("lora_cadence_class"),
        "lora_lab_profile_name": device_copy.get("lora_lab_profile_name"),
        "lora_lab_profile_confidence": device_copy.get("lora_lab_profile_confidence"),
        "lora_lab_profile_tags": device_copy.get("lora_lab_profile_tags"),
        "lora_lab_profile_source_url": device_copy.get("lora_lab_profile_source_url"),
        "lora_lab_profile_identity_family": device_copy.get("lora_lab_profile_identity_family"),
        "lora_lab_profile_role": device_copy.get("lora_lab_profile_role"),
        "lora_lab_profile_candidates": device_copy.get("lora_lab_profile_candidates"),
        "lora_identity_family": device_copy.get("lora_identity_family"),
        "lora_identity_evidence": device_copy.get("lora_identity_evidence"),
        "lora_mesh_like": device_copy.get("lora_mesh_like"),
        "lora_meter_like": device_copy.get("lora_meter_like"),
        "lora_lorawan_like": device_copy.get("lora_lorawan_like"),
        "lora_mesh_score": device_copy.get("lora_mesh_score"),
        "lora_meter_score": device_copy.get("lora_meter_score"),
        "lora_industrial_score": device_copy.get("lora_industrial_score"),
        "lora_gateway_score": device_copy.get("lora_gateway_score"),
        "lora_dwell_span_mhz": device_copy.get("lora_dwell_span_mhz"),
        "lora_frequency_count": device_copy.get("lora_frequency_count"),
        "subghz_role": device_copy.get("subghz_role"),
        "subghz_role_confidence": device_copy.get("subghz_role_confidence"),
        "subghz_operating_mode_hint": device_copy.get("subghz_operating_mode_hint"),
        "subghz_profile": device_copy.get("subghz_profile"),
        "subghz_recurring_like": device_copy.get("subghz_recurring_like"),
        "subghz_recurrence_confidence": device_copy.get("subghz_recurrence_confidence"),
        "zigbee_role": device_copy.get("zigbee_role"),
        "zigbee_role_confidence": device_copy.get("zigbee_role_confidence"),
        "zigbee_operating_mode_hint": device_copy.get("zigbee_operating_mode_hint"),
        "zigbee_mesh_like": device_copy.get("zigbee_mesh_like"),

        "hardware_id": device_copy.get("hardware_id"),
        "hardware_confidence": device_copy.get("hardware_confidence"),
        "correlation_entity_id": device_copy.get("correlation_entity_id"),
        "correlation_confidence": device_copy.get("correlation_confidence"),
        "correlation_protocols": device_copy.get("correlation_protocols"),
        "cross_protocol": device_copy.get("cross_protocol"),

        # 🔥 NEW BLE FIELDS
        "mac_address": device_copy.get("mac_address"),
        "ble_payload": device_copy.get("ble_payload"),
    }
    _sanitize_family_identity(payload)
    _apply_ble_precision_guard(payload)
    payload.update(_build_device_evidence({**device_copy, **payload}))
    return payload


def _format_devices(devices):
    return [_format_device(d) for d in devices if isinstance(d, dict)]


def _merge_device_records(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(primary or {})
    for key, value in (secondary or {}).items():
        if value in (None, "", [], {}):
            continue
        if key == "protocols":
            merged[key] = sorted(set(list(merged.get(key) or []) + list(value or [])))
        elif key in {"frequencies", "channels"}:
            merged[key] = list(dict.fromkeys(list(merged.get(key) or []) + list(value or [])))
        elif key in {"trust_reasons", "spam_reasons"}:
            merged[key] = sorted(set(list(merged.get(key) or []) + list(value or [])))
        elif key in {"seen_count", "paired_scan_response_count", "scan_response_seen_count", "crc_valid_count"}:
            merged[key] = max(_safe_int(merged.get(key)), _safe_int(value))
        elif key in {"confidence", "trust_score", "best_evidence_score", "vendor_confidence", "spam_confidence"}:
            merged[key] = max(_safe_float(merged.get(key)), _safe_float(value))
        elif key == "last_seen":
            merged[key] = max(_safe_float(merged.get(key)), _safe_float(value))
        else:
            if merged.get(key) in (None, "", [], {}):
                merged[key] = value
    return merged


def _dedupe_ble_devices(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    ble_groups: Dict[str, Dict[str, Any]] = {}

    for device in devices or []:
        if not isinstance(device, dict):
            continue
        if _record_family(device) != "ble":
            deduped.append(device)
            continue

        key = (
            str(device.get("mac_address") or "")
            or str(device.get("device_id") or "")
            or str(device.get("correlation_entity_id") or "")
        )
        if not key:
            deduped.append(device)
            continue

        if key not in ble_groups:
            ble_groups[key] = dict(device)
            continue

        ble_groups[key] = _merge_device_records(ble_groups[key], device)

    return deduped + list(ble_groups.values())


def _filter_ble_inventory_devices(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filtered: List[Dict[str, Any]] = []
    for device in devices or []:
        if not isinstance(device, dict):
            continue
        if _record_family(device) != "ble":
            filtered.append(device)
            continue
        if device.get("mac_address"):
            filtered.append(device)
    return filtered


# =============================================================================
# 🔥 DEVICE FETCH + ENRICHMENT (BLE INTEGRATED)
# =============================================================================
def _get_devices(runtime):

    if runtime is None:
        return []

    devices = _safe_call(runtime, "run_device_fusion")

    if not isinstance(devices, list):
        return []

    # ---------------------------------------------------------
    # 🔥 BLE EVENTS → DEVICES (NEW)
    # ---------------------------------------------------------
    if _ble_worker:
        try:
            ble_devices = _ble_worker.get_device_snapshot(limit=120)
            ble_recent = {
                event.get("mac_address"): event
                for event in _ble_worker.get_recent_events(limit=120)
                if isinstance(event, dict) and event.get("mac_address")
            }

            for snapshot in ble_devices:
                mac_address = snapshot.get("mac_address")
                recent = ble_recent.get(mac_address, {})
                devices.append({
                    "device_id": f"BLE-{mac_address}",
                    "protocols": ["BLE"],
                    "frequencies": [
                        snapshot.get("last_frequency_mhz")
                        or recent.get("frequency")
                    ],
                    "vendor": (
                        snapshot.get("manufacturer_company")
                        or snapshot.get("probable_vendor_family")
                        or snapshot.get("vendor")
                        or recent.get("manufacturer_company")
                        or recent.get("probable_vendor_family")
                        or recent.get("vendor")
                    ),
                    "vendor_source": (
                        snapshot.get("vendor_source")
                        or recent.get("vendor_source")
                        or ("manufacturer_company" if snapshot.get("manufacturer_company") or recent.get("manufacturer_company")
                            else ("signature_or_family" if snapshot.get("probable_vendor_family") or recent.get("probable_vendor_family") else ("oui" if snapshot.get("vendor") or recent.get("vendor") else None)))
                    ),
                    "vendor_confidence": (
                        snapshot.get("vendor_confidence")
                        or recent.get("vendor_confidence")
                        or (0.9 if snapshot.get("manufacturer_company") or recent.get("manufacturer_company")
                            else (0.72 if snapshot.get("probable_vendor_family") or recent.get("probable_vendor_family") else (0.6 if snapshot.get("vendor") or recent.get("vendor") else 0.0)))
                    ),
                    "manufacturer_company": snapshot.get("manufacturer_company") or recent.get("manufacturer_company"),
                    "manufacturer_confirmed": snapshot.get("manufacturer_confirmed"),
                    "probable_vendor_family": snapshot.get("probable_vendor_family") or recent.get("probable_vendor_family"),
                    "manufacturer_id": snapshot.get("manufacturer_id") or recent.get("manufacturer_id"),
                    "mac_address": mac_address,
                    "confidence": 0.9,
                    "ble_payload": recent.get("raw_payload"),
                    "device_type": snapshot.get("device_hint") or recent.get("device_hint") or "BLE Device",
                    "device_category": "Short-Range Wireless Device",
                    "last_seen": snapshot.get("last_seen") or recent.get("timestamp"),
                    "channels": snapshot.get("channels") or ([recent.get("channel")] if recent.get("channel") else []),
                    "seen_count": snapshot.get("seen_count"),
                    "trusted_identity": snapshot.get("trusted_identity"),
                    "trust_reasons": snapshot.get("trust_reasons"),
                    "trust_score": snapshot.get("trust_score"),
                    "privacy_state": snapshot.get("privacy_state"),
                    "spam_like": snapshot.get("spam_like"),
                    "spam_confidence": snapshot.get("spam_confidence"),
                    "spam_reasons": snapshot.get("spam_reasons"),
                    "best_evidence_score": snapshot.get("best_evidence_score"),
                    "paired_scan_response": snapshot.get("paired_scan_response"),
                    "paired_scan_response_count": snapshot.get("paired_scan_response_count"),
                    "scan_response_seen_count": snapshot.get("scan_response_seen_count"),
                    "crc_valid_count": snapshot.get("crc_valid_count"),
                })

        except Exception as e:
            print("[INTEL_API] BLE integration failed:", e)

    # ---------------------------------------------------------
    # 🔥 SIGNAL ENRICHMENT
    # ---------------------------------------------------------
    enriched_signals = _get_enriched_signals(runtime, 500)

    # ---------------------------------------------------------
    # 🔥 HARDWARE LINKING
    # ---------------------------------------------------------
    if _device_hw_linker:
        try:
            devices = _device_hw_linker.process(devices, enriched_signals)
        except Exception as e:
            print("[INTEL_API] Hardware linking failed:", e)

    # ---------------------------------------------------------
    # DEVICE INTELLIGENCE
    # ---------------------------------------------------------
    intel_engine = getattr(runtime, "device_intelligence", None)
    if intel_engine:
        try:
            if hasattr(intel_engine, "process"):
                devices = intel_engine.process(devices)
            elif hasattr(intel_engine, "enrich_devices"):
                devices = intel_engine.enrich_devices(devices)
            elif hasattr(intel_engine, "analyze_devices"):
                devices = intel_engine.analyze_devices(devices)
        except Exception as e:
            print("[INTEL_API] Device intelligence failed:", e)

    # ---------------------------------------------------------
    # IDENTITY INTELLIGENCE
    # ---------------------------------------------------------
    if _identity_intel:
        try:
            devices = _identity_intel.process(devices)
        except Exception as e:
            print("[INTEL_API] Identity intelligence failed:", e)

    # ---------------------------------------------------------
    # RF MATCHING
    # ---------------------------------------------------------
    try:
        if normalize_rf and match_yaml and load_yaml_db:

            yaml_db = load_yaml_db()

            for d in devices:
                norm = normalize_rf(d)
                match = match_yaml(norm, yaml_db)

                if match:
                    d["vendor"] = d.get("vendor") or match.get("vendor")
                    d["product"] = d.get("product") or match.get("product")
                    d["match_confidence"] = match.get("confidence")

    except Exception as e:
        print("[INTEL_API] RF enrichment failed:", e)

    # ---------------------------------------------------------
    # LORA LAB PROFILE MATCHING
    # ---------------------------------------------------------
    try:
        if _lora_lab_matcher:
            for d in devices:
                protocols = _normalize_protocol_labels(d.get("protocols") or [])
                if "LORA" not in protocols and not d.get("lora_identity_family") and not d.get("lora_bandplan"):
                    continue
                candidates = _lora_lab_matcher.rank_device(d, limit=3)
                if candidates:
                    d["lora_lab_profile_candidates"] = candidates
                match = _lora_lab_matcher.match_device(d)
                if not match:
                    continue
                d["vendor"] = d.get("vendor") or match.get("vendor")
                d["product"] = d.get("product") or match.get("product")
                d["device_type"] = d.get("device_type") or match.get("device_type")
                d["lora_lab_profile_name"] = match.get("profile_name")
                d["lora_lab_profile_confidence"] = match.get("confidence")
                d["lora_lab_profile_tags"] = match.get("tags") or []
                d["lora_lab_profile_source_url"] = match.get("source_url")
                d["lora_lab_profile_identity_family"] = match.get("identity_family")
                d["lora_lab_profile_role"] = match.get("role")
    except Exception as e:
        print("[INTEL_API] LoRa lab profile enrichment failed:", e)

    devices = _dedupe_ble_devices(devices)

    for device in devices:
        if isinstance(device, dict):
            _sanitize_family_identity(device)

    return devices


def _get_correlation_entities(runtime) -> List[Dict[str, Any]]:
    if runtime is None or not hasattr(runtime, "get_correlation_state"):
        return []
    try:
        state = runtime.get_correlation_state()
        entities = state.get("entities", [])
        return [entity for entity in entities if isinstance(entity, dict)]
    except Exception:
        return []


def _find_signal_by_id(runtime, signal_id: str) -> Dict[str, Any] | None:
    if runtime is None:
        return None
    signal_engine = getattr(runtime, "signal", None)
    if signal_engine is None:
        return None
    try:
        if hasattr(signal_engine, "get_signal_by_id"):
            return signal_engine.get_signal_by_id(signal_id)
        if hasattr(signal_engine, "get_signal"):
            return signal_engine.get_signal(signal_id)
    except Exception:
        return None
    return None


def _find_device_by_id(runtime, device_id: str) -> Dict[str, Any] | None:
    devices = _get_devices(runtime)
    for device in devices:
        if str(device.get("device_id")) == str(device_id):
            return device
    return None


# =============================================================================
# REMAINING API (UNCHANGED)
# =============================================================================
@router.get("/summary")
def intel_summary(request: Request):

    runtime = _get_runtime(request)

    signal = getattr(runtime, "signal", None)
    summary = _safe_call(signal, "get_summary") or {}

    raw_devices = _get_devices(runtime)
    devices = _format_devices(raw_devices)

    identity_hits = 0
    fingerprint_hits = 0
    vendors = {}

    for d in raw_devices:

        identity, fingerprint = _extract_intelligence(d)

        if identity.get("identity_present"):
            identity_hits += 1

        if fingerprint:
            fingerprint_hits += 1

        v = identity.get("vendor")
        if v:
            vendors[v] = vendors.get(v, 0) + 1

    return {
        "signal_count": _safe_int(summary.get("signal_count")),
        "active_signal_count": _safe_int(summary.get("active_signal_count")),
        "real_protocol_signals": _safe_int(summary.get("real_protocol_signals")),
        "confident_real_protocol_signals": _safe_int(summary.get("confident_real_protocol_signals")),
        "signals_with_device_hints": _safe_int(summary.get("signals_with_device_hints")),
        "protocol_counts": summary.get("protocol_counts", {}),
        "band_counts": summary.get("band_counts", {}),
        "device_fusion_available": True,
        "device_intelligence_available": True,
        "device_count": len(devices),
        "identity_hits": identity_hits,
        "fingerprint_hits": fingerprint_hits,
        "vendors": vendors,
        "devices": devices,
        "timestamp": time.time(),
    }


@router.get("/devices")
def intel_devices(request: Request):

    runtime = _get_runtime(request)
    devices = _format_devices(_get_devices(runtime))

    return {
        "count": len(devices),
        "devices": devices,
        "timestamp": time.time(),
    }


@router.get("/signals")
def intel_signals(request: Request, limit: int = Query(100, ge=1, le=1000)):

    runtime = _get_runtime(request)
    raw = _get_enriched_signals(runtime, limit)

    return {
        "count": len(raw),
        "signals": raw,
        "timestamp": time.time(),
    }


@router.get("/ble/decoder/status")
def ble_decoder_status(request: Request):
    _get_runtime(request)
    return _get_ble_decoder_status()


@router.post("/ble/decoder/start")
def ble_decoder_start(request: Request):
    runtime = _get_runtime(request)
    _ensure_ble_worker_running(runtime)
    return _get_ble_decoder_status()


@router.post("/ble/decoder/stop")
def ble_decoder_stop(request: Request):
    _get_runtime(request)
    _stop_ble_worker()
    return _get_ble_decoder_status()


@router.post("/ble/decoder/clear")
def ble_decoder_clear(request: Request):
    _get_runtime(request)
    if _ble_worker and hasattr(_ble_worker, "clear_runtime_state"):
        _ble_worker.clear_runtime_state()
    return _get_ble_decoder_status()


@router.get("/storage")
def intel_storage(request: Request):

    runtime = _get_runtime(request)
    signal = getattr(runtime, "signal", None)

    stats = _safe_call(signal, "get_stats") or {}

    count = _safe_int(stats.get("active_signals"))

    return {
        "signal_count": count,
        "active_signal_count": count,
        "timestamp": time.time(),
    }


@router.get("/top")
def intel_top(request: Request, limit: int = Query(25, ge=1, le=1000)):

    runtime = _get_runtime(request)
    raw = _get_enriched_signals(runtime, limit)

    return {
        "count": len(raw),
        "signals": raw,
        "timestamp": time.time(),
    }


def _reset_runtime_rf_buffers(runtime: Any) -> None:
    if runtime is None:
        return
    signal_engine = getattr(runtime, "signal", None)
    if signal_engine and hasattr(signal_engine, "reset"):
        signal_engine.reset()
    device_fusion = getattr(runtime, "device_fusion", None)
    if device_fusion and hasattr(device_fusion, "reset"):
        device_fusion.reset()


def _build_band_response(runtime: Any, band: str, limit: int = 200, active_only: bool = True) -> Dict[str, Any]:
    raw_signals = _get_enriched_signals(
        runtime,
        limit=max(limit * 4, 200),
        active_only=active_only,
        sort_by="last_seen",
    )
    band_signals = _filter_signals_for_band(raw_signals, band)[:limit]
    devices = _format_devices(_get_devices(runtime))
    matched_devices = _match_devices_for_signals(band_signals, devices, band)
    matched_devices = [
        device for device in matched_devices
        if _record_matches_band(device, band) and _family_frequency_compatible(device, band)
    ]
    if str(band or "").lower() == "ble":
        matched_devices = _filter_ble_inventory_devices(matched_devices)
    correlated_entities = []
    seen_entity_ids = set()
    for entity in _get_correlation_entities(runtime):
        if not isinstance(entity, dict):
            continue
        entity_id = str(entity.get("entity_id") or "")
        if entity_id and entity_id in seen_entity_ids:
            continue
        protocols = {str(proto).lower() for proto in entity.get("protocols") or []}
        rf_bands = {str(rf_band).lower() for rf_band in entity.get("rf_bands") or []}
        target = str(band or "").lower()
        if (
            target in protocols
            or target.replace("-", "") in {proto.replace("-", "") for proto in protocols}
            or target in rf_bands
            or (
                target == "iot"
                and (
                    protocols & {"ble", "zigbee", "thread", "lora", "wireless_mbus", "proprietary_iot"}
                    or any(hint in str(entity).lower() for hint in _IOT_TEXT_HINTS)
                )
            )
        ):
            if entity_id:
                seen_entity_ids.add(entity_id)
            correlated_entities.append(entity)

    capability = _tab_band_capability(band, runtime)
    sweep_state = _sdr_sweep_manager.get_state(str(band or "").upper())
    return {
        "band": str(band or "").upper(),
        "signal_count": len(band_signals),
        "matched_device_count": len(matched_devices),
        "signals": band_signals,
        "devices": matched_devices[:20],
        "correlated_entities": correlated_entities[:20],
        "indicators": _extract_band_indicators(band, band_signals, matched_devices),
        "capability": capability,
        "sweep": sweep_state,
        "timestamp": time.time(),
    }


@router.get("/sweep/state")
def intel_sweep_state(request: Request, band: str):
    runtime = _get_runtime(request)
    return {
        "band": str(band or "").upper(),
        "capability": _tab_band_capability(band, runtime),
        "sweep": _sdr_sweep_manager.get_state(str(band or "").upper()),
        "timestamp": time.time(),
    }


@router.post("/sweep/start")
def intel_sweep_start(request: Request, band: str, duration_minutes: float = 0.0):
    runtime = _get_runtime(request)
    capability = _tab_band_capability(band, runtime)
    if not capability.get("can_sweep"):
        return {
            "status": "blocked",
            "capability": capability,
            "sweep": _sdr_sweep_manager.get_state(str(band or "").upper()),
            "timestamp": time.time(),
        }
    if runtime is None or not getattr(runtime, "session_controller", None) or not runtime.session_controller.is_active():
        return {
            "status": "blocked",
            "error": "Start Session first. Sweep jobs require an active SDR session.",
            "capability": capability,
            "sweep": _sdr_sweep_manager.get_state(str(band or "").upper()),
            "timestamp": time.time(),
        }
    result = _sdr_sweep_manager.start(
        str(band or "").upper(),
        duration_minutes=duration_minutes,
        snapshot_fn=lambda active_tab, channel: _build_band_response(runtime, active_tab, limit=120, active_only=True),
        retune_fn=lambda freq_mhz: runtime.session_controller.retune(freq_mhz),
        reset_runtime_fn=lambda: _reset_runtime_rf_buffers(runtime),
    )
    result["capability"] = capability
    result["timestamp"] = time.time()
    return result


@router.post("/sweep/stop")
def intel_sweep_stop(request: Request, band: str):
    runtime = _get_runtime(request)
    result = _sdr_sweep_manager.stop(str(band or "").upper())
    result["capability"] = _tab_band_capability(band, runtime)
    result["timestamp"] = time.time()
    return result


@router.post("/sweep/clear")
def intel_sweep_clear(request: Request, band: str):
    runtime = _get_runtime(request)
    result = _sdr_sweep_manager.clear(
        str(band or "").upper(),
        reset_runtime_fn=lambda: _reset_runtime_rf_buffers(runtime),
    )
    result["capability"] = _tab_band_capability(band, runtime)
    result["timestamp"] = time.time()
    return result


@router.get("/band/{band}")
def intel_band(band: str, request: Request, limit: int = Query(200, ge=1, le=1000)):
    runtime = _get_runtime(request)
    return _build_band_response(runtime, band, limit=limit, active_only=True)


@router.get("/correlations")
def intel_correlations(request: Request):

    runtime = _get_runtime(request)
    entities = _get_correlation_entities(runtime)

    return {
        "count": len(entities),
        "entities": entities,
        "timestamp": time.time(),
    }


@router.get("/lora/profiles")
def intel_lora_profiles():

    if not _lora_lab_matcher:
        return {
            "count": 0,
            "profiles": [],
            "timestamp": time.time(),
        }

    profiles = _lora_lab_matcher.load_profiles()
    cleaned = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        cleaned.append(
            {
                "profile_name": profile.get("profile_name"),
                "vendor": profile.get("vendor"),
                "product": profile.get("product"),
                "device_type": profile.get("device_type"),
                "bandplan": profile.get("bandplan"),
                "region": profile.get("region"),
                "cadence_class": profile.get("cadence_class"),
                "identity_family": profile.get("identity_family"),
                "role": profile.get("role"),
                "center_freq_mhz": profile.get("center_freq_mhz"),
                "tags": profile.get("tags") or [],
                "source_url": profile.get("source_url"),
            }
        )

    return {
        "count": len(cleaned),
        "profiles": cleaned,
        "timestamp": time.time(),
    }


@router.get("/iot/profiles")
def intel_iot_profiles(request: Request):
    runtime = _get_runtime(request)
    profiles = _get_iot_profile_inventory(runtime)
    return {
        "count": len(profiles),
        "profiles": profiles,
        "timestamp": time.time(),
    }


@router.get("/signal/{signal_id}")
def intel_signal_detail(signal_id: str, request: Request):

    runtime = _get_runtime(request)
    signal = _find_signal_by_id(runtime, signal_id)

    if signal is None:
        return {"error": "signal_not_found", "signal_id": signal_id, "timestamp": time.time()}

    return {
        "signal": signal,
        "timestamp": time.time(),
    }


@router.get("/device/{device_id}")
def intel_device_detail(device_id: str, request: Request):

    runtime = _get_runtime(request)
    device = _find_device_by_id(runtime, device_id)

    if device is None:
        return {"error": "device_not_found", "device_id": device_id, "timestamp": time.time()}

    return {
        "device": _format_device(device),
        "timestamp": time.time(),
    }


@router.get("/health")
def intel_health(request: Request):

    runtime = _get_runtime(request)

    return {
        "status": "ok" if runtime else "degraded",
        "timestamp": time.time(),
    }
