from __future__ import annotations

import json
import os
import re
import select
import signal
import shutil
import subprocess
import threading
import time
import html
from hashlib import sha1
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List
from xml.etree import ElementTree as ET

from backend.config.project_config import ROOT_DIR, get_project_config
from backend.integrations.ble_normalizer import normalize_observation
from backend.integrations.classification_engine import CLASSIFICATION_LABELS, classify_cluster
from backend.integrations.confidence_engine import compute_confidence
from backend.integrations.ble_intelligence_engine import BLEIntelligenceEngine
from backend.integrations.identity_engine import cluster_devices
from backend.integrations.ble_validation_engine import BLEValidationEngine

try:
    import serial
except Exception:  # pragma: no cover - optional runtime dependency
    serial = None

try:
    import gi
    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib
except Exception:  # pragma: no cover - optional runtime dependency
    Gio = None
    GLib = None

class BLENR5Controller:
    VERSION = "1.0.0"
    DEFAULT_PROFILE = "production_monitoring"
    DEFAULT_CHANNELS = [37, 38, 39]
    DEFAULT_SCAN_SECONDS = 60
    NORDIC_SNIFFER_RATES = [1000000, 460800]
    NORDIC_ADV_ACCESS_ADDRESS = bytes.fromhex("d6be898e")
    BLE_PDU_TYPES = {
        0x00: "adv_ind",
        0x01: "adv_direct_ind",
        0x02: "adv_nonconn_ind",
        0x04: "scan_rsp",
        0x06: "adv_scan_ind",
    }
    COMPANY_IDS = {
        0x0006: "Microsoft",
        0x000F: "Broadcom",
        0x004C: "Apple",
        0x0059: "Nordic Semiconductor",
        0x0075: "Samsung",
        0x00E0: "Google",
        0x0131: "Sony",
        0x015D: "Fitbit",
        0x0183: "Garmin",
        0x02E5: "Tile",
    }
    SERVICE_VENDOR_HINTS = {
        "feaa": "Google",
        "fe2c": "Apple",
        "fd6f": "Tile",
    }
    PERSONAL_VENDORS = {
        "Apple",
        "Samsung",
        "Google",
        "Sony",
        "Fitbit",
        "Garmin",
        "Tile",
    }
    IOT_VENDORS = {
        "Aqara",
        "Arlo",
        "August",
        "Belkin",
        "Ecobee",
        "Eufy",
        "IKEA",
        "Nest",
        "Philips",
        "Ring",
        "Sonos",
        "TP-Link",
        "Tuya",
        "Xiaomi",
        "Wyze",
    }
    ZIGBEE_INFERENCE_VENDORS = {
        "Aqara",
        "IKEA",
        "Philips",
        "Xiaomi",
    }
    CLOUD_ECOSYSTEM_VENDORS = {
        "Arlo",
        "August",
        "Belkin",
        "Ecobee",
        "Eufy",
        "Google",
        "Nest",
        "Ring",
        "Samsung",
        "Sonos",
        "TP-Link",
        "Tuya",
        "Wyze",
    }
    GATT_DFU_UUID_HINTS = {
        "0000fe59-0000-1000-8000-00805f9b34fb",
        "fe59",
        "8ec90003-f315-4f60-9fb8-838830daea50",
        "00060000-f8ce-11e4-abf4-0002a5d5c51b",
        "f000ffc0-0451-4000-b000-000000000000",
    }
    TARGET_CLASS_PACKS = {
        "audio": {
            "family": "audio_accessory",
            "product_class": "audio",
            "exploit_families": ["fast_pair_abuse", "microphone_abuse", "tracking_abuse"],
        },
        "hid": {
            "family": "input_peripheral",
            "product_class": "hid",
            "exploit_families": ["hid_impersonation", "reconnect_abuse", "just_works_abuse"],
        },
        "smart_lock": {
            "family": "access_control",
            "product_class": "lock",
            "exploit_families": ["unauthorized_unlock", "gatt_control_surface", "trust_downgrade"],
        },
        "wearable": {
            "family": "wearable_tracker",
            "product_class": "wearable",
            "exploit_families": ["tracking_abuse", "privacy_leakage", "firmware_family_exposure"],
        },
        "vehicle": {
            "family": "vehicle_accessory",
            "product_class": "vehicle",
            "exploit_families": ["proximity_tracking", "firmware_family_exposure", "control_surface_mapping"],
        },
        "medical_device": {
            "family": "medical_peripheral",
            "product_class": "medical",
            "exploit_families": ["telemetry_exposure", "trust_downgrade", "gatt_control_surface"],
        },
        "industrial_gateway": {
            "family": "sensor_gateway",
            "product_class": "industrial",
            "exploit_families": ["telemetry_exposure", "gatt_control_surface", "firmware_family_exposure"],
        },
        "general": {
            "family": "generic_ble",
            "product_class": "general",
            "exploit_families": ["fingerprint_needed"],
        },
    }
    DEVICE_TYPE_HINTS = [
        ("airpods", "earbuds", "audio"),
        ("earbuds", "earbuds", "audio"),
        ("earbud", "earbuds", "audio"),
        ("buds", "earbuds", "audio"),
        ("headset", "headset", "audio"),
        ("headphone", "headphones", "audio"),
        ("soundlink", "speaker", "audio"),
        ("bose", "speaker", "audio"),
        ("speaker", "speaker", "audio"),
        ("watch", "watch", "wearable"),
        ("band", "fitness band", "wearable"),
        ("fitbit", "fitness band", "wearable"),
        ("tile", "tracker", "tracker"),
        ("tracker", "tracker", "tracker"),
        ("airtag", "tracker", "tracker"),
        ("flipper", "security multitool", "general"),
        ("keyboard", "keyboard", "hid"),
        ("mouse", "mouse", "hid"),
        ("trackpad", "trackpad", "hid"),
        ("lock", "smart lock", "smart_lock"),
        ("tesla", "vehicle", "vehicle"),
        ("bmw", "vehicle", "vehicle"),
        ("ford", "vehicle", "vehicle"),
        ("gateway", "gateway", "industrial_gateway"),
        ("sensor", "sensor", "industrial_gateway"),
        ("beacon", "beacon", "general"),
    ]
    VALIDATION_SCENARIOS = {
        "pairing_posture": {
            "id": "pairing_posture",
            "label": "Pairing Posture",
            "layer": "pairing",
            "summary": "Evaluate connectability, likely pairing posture, and user-confirmation strength.",
        },
        "bond_lifecycle": {
            "id": "bond_lifecycle",
            "label": "Bond Lifecycle",
            "layer": "bonding",
            "summary": "Track re-pair, bond replacement, trust changes, and lifecycle anomalies.",
        },
        "reconnect_resilience": {
            "id": "reconnect_resilience",
            "label": "Reconnect Resilience",
            "layer": "reconnect",
            "summary": "Measure how the device behaves across controlled disconnect and reconnect attempts.",
        },
        "gatt_surface": {
            "id": "gatt_surface",
            "label": "GATT Surface",
            "layer": "gatt",
            "summary": "Enumerate services, characteristics, writable surfaces, and likely sensitive controls.",
        },
        "misuse_interactions": {
            "id": "misuse_interactions",
            "label": "Misuse Interactions",
            "layer": "validation",
            "summary": "Assess non-ideal but lawful lab interactions and whether the device degrades safely.",
        },
    }

    def __init__(self, root_dir: Path | None = None) -> None:
        self.root_dir = Path(root_dir or ROOT_DIR)
        self.log_dir = self.root_dir / "logs" / "ble_nr5"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.observation_log = self.log_dir / "observations.jsonl"
        self.timeline_log = self.log_dir / "timeline.jsonl"
        self.task_state_path = self.log_dir / "workflow_tasks.json"
        self.resolution_cache_path = self.log_dir / "resolution_cache.json"
        self.identity_graph_path = self.log_dir / "identity_graph.json"
        self.operation_lock_dir = self.log_dir / "device_ops"
        self.operation_lock_dir.mkdir(parents=True, exist_ok=True)
        self.target_session_lock_dir = self.log_dir / "target_sessions"
        self.target_session_lock_dir.mkdir(parents=True, exist_ok=True)
        self.knowledge_path = self.root_dir / "config" / "ble_nr5_knowledge_base.json"
        self.fingerprint_db_path = self.root_dir / "backend" / "config" / "ble_fingerprint_db.json"
        self.active = False
        self.started_at: float | None = None
        self.last_error = ""
        self.last_profile = self.DEFAULT_PROFILE
        self.last_mission = "asset_discovery"
        self.lab_mode = False
        self.classic_sidecar = False
        self.sensor_selection: List[str] = []
        self._scan_lock = threading.Lock()
        self._live_hunt_lock = threading.Lock()
        self._live_hunt_stop_event = threading.Event()
        self._live_hunt_thread: threading.Thread | None = None
        self.live_hunt_state: Dict[str, Any] = self._default_live_hunt_state()
        self._knowledge_base = self._load_knowledge_base()
        self.scan_stages: List[Dict[str, Any]] = []
        self.last_scan: Dict[str, Any] = {}
        self.gatt_engine_state: Dict[str, Any] = {
            "status": "idle",
            "device_key": "",
            "device_name": "",
            "summary": "GATT engine idle",
            "stages": [],
            "updated_at": None,
        }
        self.identity_engine_state: Dict[str, Any] = {
            "status": "idle",
            "summary": "Identity correlation engine idle",
            "stages": [],
            "node_count": 0,
            "resolved_hosts": 0,
            "correlated_nodes": 0,
            "updated_at": None,
        }
        self.hard_test_state: Dict[str, Any] = {
            "status": "idle",
            "device_key": "",
            "device_name": "",
            "summary": "Hard BLE test idle",
            "stages": [],
            "updated_at": None,
        }
        self.active_tools: List[str] = []
        self.last_tool_errors: List[str] = []
        self._serial_probe_cache: Dict[str, Dict[str, Any]] = {}
        self._bluez_bus_connection = None
        self._device_operation_lock = threading.Lock()
        self._device_operations: Dict[str, Dict[str, Any]] = {}
        self._target_session_lock = threading.Lock()
        self._target_sessions: Dict[str, Dict[str, Any]] = {}
        self._identity_graph_cache: Dict[str, Any] | None = None
        self.ble_intelligence_engine = BLEIntelligenceEngine(self.fingerprint_db_path)
        self.validation_engine = BLEValidationEngine(
            self.root_dir,
            run_command=self._run_capture_command,
            run_bluetoothctl_session=self._run_bluetoothctl_session,
            parse_bluetoothctl_info=self._parse_bluetoothctl_info,
            parse_bluetoothctl_gatt=self._parse_bluetoothctl_gatt,
            bluez_fetch_device_info=self._bluez_fetch_device_info,
            bluez_run_validation_session=self._bluez_run_validation_session,
        )

    def _default_validation_scenario_ids(self) -> list[str]:
        return list(self.VALIDATION_SCENARIOS.keys())

    def _default_live_hunt_state(self) -> Dict[str, Any]:
        return {
            "active": False,
            "status": "idle",
            "detail": "Live Hunt idle",
            "scan_seconds": self.DEFAULT_SCAN_SECONDS,
            "started_at": None,
            "stopped_at": None,
            "last_cycle_started_at": None,
            "last_cycle_completed_at": None,
            "cycle_count": 0,
            "last_cycle_observation_count": 0,
            "last_cycle_device_count": 0,
            "heartbeat_at": None,
        }

    def _live_hunt_snapshot(self) -> Dict[str, Any]:
        with self._live_hunt_lock:
            return dict(self.live_hunt_state)

    def _set_live_hunt_state(self, **updates: Any) -> Dict[str, Any]:
        with self._live_hunt_lock:
            current = dict(self.live_hunt_state)
            current.update(updates)
            self.live_hunt_state = current
            return dict(self.live_hunt_state)

    def _load_knowledge_base(self) -> Dict[str, Any]:
        if not self.knowledge_path.exists():
            return {}
        try:
            return json.loads(self.knowledge_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _read_json_object(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _write_json_object(self, path: Path, payload: Dict[str, Any]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        except OSError as exc:
            self.last_error = f"Unable to persist runtime JSON at {path}: {exc}"

    def _run_command(self, cmd: list[str], timeout: float = 5.0) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return (result.stdout or result.stderr or "").strip()
        except Exception:
            return ""

    def _run_capture_command(self, cmd: list[str], timeout: float = 10.0) -> Dict[str, Any]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return {
                "ok": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
            }
        except Exception as exc:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": str(exc),
            }

    def _bluez_device_path(self, address: str, adapter: str = "") -> str:
        normalized = str(address or "").strip().upper().replace(":", "_")
        adapter_name = str(adapter or "").strip()
        if not adapter_name:
            adapter_name = self._bluez_adapter_path().rsplit("/", 1)[-1]
        return f"/org/bluez/{adapter_name}/dev_{normalized}"

    def _bluez_dbus_available(self) -> bool:
        return bool(self._bluez_runtime_status().get("available"))

    def _bluez_runtime_status(self) -> Dict[str, Any]:
        dbus_send_path = shutil.which("dbus-send") or ""
        busctl_path = shutil.which("busctl") or ""
        system_bus_ready = Path("/run/dbus/system_bus_socket").exists()
        status = {
            "available": False,
            "dbus_send_path": dbus_send_path,
            "busctl_path": busctl_path,
            "system_bus_ready": system_bus_ready,
            "service_registered": False,
            "detail": "",
        }
        if not dbus_send_path or not busctl_path:
            status["detail"] = "dbus-send or busctl is not installed on this host."
            return status
        if not system_bus_ready:
            status["detail"] = "System DBus socket is not present on this host."
            return status
        owner_result = self._run_capture_command(
            [
                dbus_send_path,
                "--system",
                "--dest=org.freedesktop.DBus",
                "--type=method_call",
                "--print-reply",
                "/",
                "org.freedesktop.DBus.NameHasOwner",
                "string:org.bluez",
            ],
            timeout=4.0,
        )
        owner_output = "\n".join(
            [
                str(owner_result.get("stdout") or "").strip(),
                str(owner_result.get("stderr") or "").strip(),
            ]
        ).strip()
        lowered = owner_output.lower()
        if "boolean true" in lowered:
            status["available"] = True
            status["service_registered"] = True
            status["detail"] = "BlueZ DBus service is available."
            return status
        if "boolean false" in lowered or "serviceunknown" in lowered or "namehasowner" in lowered:
            status["detail"] = "BlueZ service is not registered on the system bus."
            return status
        status["detail"] = owner_output or "Unable to confirm BlueZ DBus service availability."
        return status

    def _bluez_adapter_inventory(self, timeout: float = 6.0) -> List[Dict[str, Any]]:
        adapters: List[Dict[str, Any]] = []
        payload = self._bluez_managed_objects_json(timeout=timeout)
        data = payload.get("data")
        if isinstance(data, list) and data:
            objects = self._unwrap_busctl_variant(data[0])
            if isinstance(objects, dict):
                for path, interfaces in objects.items():
                    if not isinstance(interfaces, dict):
                        continue
                    props = interfaces.get("org.bluez.Adapter1")
                    if not isinstance(props, dict):
                        continue
                    adapters.append(
                        {
                            "path": str(path),
                            "name": str(path).rsplit("/", 1)[-1],
                            "address": str(props.get("Address") or "").upper(),
                            "powered": bool(props.get("Powered")),
                            "discovering": bool(props.get("Discovering")),
                            "pairable": bool(props.get("Pairable")),
                            "discoverable": bool(props.get("Discoverable")),
                        }
                    )
        if adapters:
            return adapters
        hciconfig_path = shutil.which("hciconfig") or ""
        if not hciconfig_path:
            return adapters
        result = self._run_capture_command([hciconfig_path, "-a"], timeout=timeout)
        current: Dict[str, Any] | None = None
        for raw in str(result.get("stdout") or result.get("stderr") or "").splitlines():
            line = raw.rstrip()
            if not line:
                continue
            if not line.startswith("\t") and ":" in line:
                if current:
                    adapters.append(current)
                name = line.split(":", 1)[0].strip()
                current = {
                    "path": f"/org/bluez/{name}",
                    "name": name,
                    "address": "",
                    "powered": "up running" in line.lower(),
                    "discovering": False,
                    "pairable": False,
                    "discoverable": False,
                }
                continue
            if current is None:
                continue
            stripped = line.strip()
            lowered = stripped.lower()
            if stripped.startswith("BD Address:"):
                current["address"] = stripped.split("BD Address:", 1)[1].split(None, 1)[0].strip().upper()
            if "up running" in lowered:
                current["powered"] = True
            if "pscan" in lowered:
                current["pairable"] = True
            if "iscan" in lowered:
                current["discoverable"] = True
        if current:
            adapters.append(current)
        return adapters

    def _bluez_host_readiness(self) -> Dict[str, Any]:
        runtime = self._bluez_runtime_status()
        adapters = self._bluez_adapter_inventory()
        powered_adapters = [item for item in adapters if bool(item.get("powered"))]
        ready = bool(runtime.get("available")) and bool(powered_adapters)
        state = "ready"
        detail = "BlueZ and at least one powered adapter are available."
        next_action = ""
        if not runtime.get("dbus_send_path") or not runtime.get("busctl_path"):
            state = "missing_tools"
            detail = "dbus-send or busctl is not installed on this host."
            next_action = "Install the BlueZ DBus tooling before running active BLE validation."
        elif not bool(runtime.get("system_bus_ready")):
            state = "system_bus_unavailable"
            detail = "System DBus socket is not present on this host."
            next_action = "Start the system DBus service before running BLE validation."
        elif not bool(runtime.get("service_registered")):
            state = "service_unregistered"
            detail = str(runtime.get("detail") or "BlueZ service is not registered on the system bus.")
            next_action = "Start or repair the BlueZ bluetooth service on the host."
        elif not adapters:
            state = "adapter_missing"
            detail = "BlueZ is present but no Bluetooth adapter is visible to the host."
            next_action = "Attach or recover a Bluetooth adapter before active validation."
        elif not powered_adapters:
            state = "adapter_unpowered"
            detail = "Bluetooth adapter is visible but not powered."
            next_action = "Power on the host Bluetooth adapter before active validation."
        return {
            "ready": ready,
            "state": state,
            "detail": detail,
            "next_action": next_action,
            "runtime": runtime,
            "adapters": adapters[:6],
            "powered_adapter_count": len(powered_adapters),
            "adapter_count": len(adapters),
        }

    def _bluez_gio_available(self) -> bool:
        return Gio is not None and GLib is not None and Path("/run/dbus/system_bus_socket").exists()

    def _bluez_bus(self):
        if not self._bluez_gio_available():
            return None
        if self._bluez_bus_connection is not None:
            return self._bluez_bus_connection
        try:
            self._bluez_bus_connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        except Exception:
            self._bluez_bus_connection = None
        return self._bluez_bus_connection

    def _bluez_variant_to_python(self, value: Any) -> Any:
        if GLib is not None and isinstance(value, GLib.Variant):
            return self._bluez_variant_to_python(value.unpack())
        if isinstance(value, dict):
            return {str(key): self._bluez_variant_to_python(val) for key, val in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._bluez_variant_to_python(item) for item in value]
        return value

    def _bluez_gio_call(self, path: str, interface: str, member: str, parameters: Any = None, timeout: float = 10.0) -> Dict[str, Any]:
        bus = self._bluez_bus()
        if bus is None or Gio is None:
            return {"ok": False, "error": "gio_unavailable", "detail": "PyGObject Gio is not available"}
        method = f"{interface}.{member}"
        try:
            result = bus.call_sync(
                "org.bluez",
                path,
                interface,
                member,
                parameters,
                None,
                Gio.DBusCallFlags.NONE,
                int(max(1000, timeout * 1000)),
                None,
            )
            unpacked = self._bluez_variant_to_python(result) if result is not None else None
            return {"ok": True, "result": unpacked, "detail": method}
        except Exception as exc:
            return {"ok": False, "error": member.lower(), "detail": str(exc), "method": method}

    def _bluez_busctl_json_call(self, path: str, interface: str, member: str, signature: str = "", args: list[str] | None = None, timeout: float = 10.0) -> Dict[str, Any]:
        cmd = [
            "busctl",
            "--json=short",
            "call",
            "org.bluez",
            path,
            interface,
            member,
        ]
        if signature:
            cmd.append(signature)
        if args:
            cmd.extend(args)
        result = self._run_capture_command(cmd, timeout=timeout)
        payload: Dict[str, Any] = {"ok": bool(result.get("ok")), "stdout": result.get("stdout") or "", "stderr": result.get("stderr") or ""}
        if result.get("ok") and result.get("stdout"):
            try:
                decoded = json.loads(result["stdout"])
                if isinstance(decoded, dict):
                    payload["json"] = decoded
            except Exception:
                payload["json"] = {}
        return payload

    def _bluez_managed_objects_json(self, timeout: float = 8.0) -> Dict[str, Any]:
        if self._bluez_gio_available():
            response = self._bluez_gio_call("/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", timeout=timeout)
            if response.get("ok"):
                result = response.get("result")
                if isinstance(result, list) and result:
                    root = result[0]
                    if isinstance(root, dict):
                        return {"data": [root]}
        result = self._bluez_busctl_json_call(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects",
            timeout=timeout,
        )
        payload = result.get("json")
        if isinstance(payload, dict):
            return payload
        return {}

    def _unwrap_busctl_variant(self, node: Any) -> Any:
        if isinstance(node, dict):
            if "data" in node and "type" in node and len(node) <= 3:
                return self._unwrap_busctl_variant(node.get("data"))
            return {str(key): self._unwrap_busctl_variant(value) for key, value in node.items()}
        if isinstance(node, list):
            if len(node) == 1 and isinstance(node[0], dict):
                return self._unwrap_busctl_variant(node[0])
            return [self._unwrap_busctl_variant(item) for item in node]
        return node

    def _resolution_cache_map(self) -> Dict[str, Dict[str, Any]]:
        payload = self._read_json_object(self.resolution_cache_path)
        items = payload.get("devices")
        return items if isinstance(items, dict) else {}

    def _save_resolution_cache_map(self, cache: Dict[str, Dict[str, Any]]) -> None:
        self._write_json_object(
            self.resolution_cache_path,
            {
                "devices": cache,
                "updated_at": time.time(),
            },
        )

    def _cache_resolution(self, device_key: str, record: Dict[str, Any]) -> None:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return
        cache = self._resolution_cache_map()
        cache[normalized_key] = dict(record)
        self._save_resolution_cache_map(cache)

    def _cached_resolution(self, device_key: str) -> Dict[str, Any]:
        return self._resolution_cache_map().get(str(device_key or "").strip().lower(), {})

    def _identity_graph_payload(self) -> Dict[str, Any]:
        if self._identity_graph_cache is not None:
            return self._identity_graph_cache
        payload = self._read_json_object(self.identity_graph_path)
        if not isinstance(payload.get("nodes"), list):
            payload = {"nodes": [], "updated_at": 0}
        self._identity_graph_cache = payload
        return payload

    def _save_identity_graph_payload(self, payload: Dict[str, Any]) -> None:
        self._identity_graph_cache = payload
        self._write_json_object(self.identity_graph_path, payload)

    def _payload_signature_hash(self, service_uuids: List[str], manufacturer_prefix: str, packet_length: int, structure_count: int, adv_flags: Any) -> str:
        signature = {
            "service_uuids": sorted(str(item).lower() for item in (service_uuids or [])),
            "manufacturer_prefix": str(manufacturer_prefix or "").lower(),
            "packet_length": int(packet_length or 0),
            "structure_count": int(structure_count or 0),
            "adv_flags": adv_flags if adv_flags is not None else "",
        }
        return sha1(json.dumps(signature, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    def _extract_identity_features(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        service_uuids = sorted(str(item).lower() for item in (observation.get("service_uuids") or []))
        manufacturer_prefix = str(observation.get("manufacturer_data_prefix") or "").lower()
        packet_length = int(observation.get("packet_length") or 0)
        structure_count = int(observation.get("ad_structure_count") or 0)
        adv_flags = observation.get("adv_flags")
        return {
            "rf_address": str(observation.get("address") or "").lower(),
            "public_prefix": ":".join(str(observation.get("address") or "").lower().split(":")[:3]),
            "address_type": str(observation.get("address_type") or "").lower(),
            "timestamp": float(observation.get("timestamp") or time.time()),
            "rssi": observation.get("rssi"),
            "manufacturer_company_id": observation.get("manufacturer_company_id"),
            "service_uuids": service_uuids,
            "manufacturer_prefix": manufacturer_prefix,
            "packet_length": packet_length,
            "structure_count": structure_count,
            "adv_flags": adv_flags,
            "payload_signature_hash": self._payload_signature_hash(service_uuids, manufacturer_prefix, packet_length, structure_count, adv_flags),
            "asset_key": str(observation.get("asset_key") or "").strip().lower(),
            "device_type": str(observation.get("device_type") or "bluetooth device"),
            "vendor": str(observation.get("vendor") or observation.get("manufacturer") or "Unknown"),
            "name": str(observation.get("name") or "Unknown BLE Device"),
        }

    def _rolling_stats(self, values: List[float]) -> Dict[str, float]:
        if not values:
            return {"mean": 0.0, "variance": 0.0, "slope": 0.0}
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        slope = 0.0
        if len(values) > 1:
            slope = values[-1] - values[0]
        return {"mean": round(mean, 3), "variance": round(variance, 3), "slope": round(slope, 3)}

    def _sequence_similarity(self, left: List[float], right: List[float], tolerance: float) -> float:
        if not left or not right:
            return 0.0
        left_mean = sum(left) / len(left)
        right_mean = sum(right) / len(right)
        delta = abs(left_mean - right_mean)
        if tolerance <= 0:
            return 0.0
        return max(0.0, 1.0 - min(1.0, delta / tolerance))

    def _jaccard_similarity(self, left: List[str], right: List[str]) -> float:
        left_set = {str(item).lower() for item in (left or []) if str(item).strip()}
        right_set = {str(item).lower() for item in (right or []) if str(item).strip()}
        if not left_set or not right_set:
            return 0.0
        union = left_set.union(right_set)
        if not union:
            return 0.0
        return len(left_set.intersection(right_set)) / len(union)

    def _observation_to_identity_score(self, observation: Dict[str, Any], node: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_identity_features(observation)
        node_intervals = [float(item) for item in (node.get("temporal_pattern") or []) if float(item) >= 0]
        node_rssi = [float(item) for item in (node.get("rssi_series") or []) if item is not None]
        observation_timestamp = float(features.get("timestamp") or time.time())
        temporal_delta = abs(observation_timestamp - float(node.get("last_seen") or observation_timestamp))
        temporal_similarity = 1.0 if temporal_delta <= 4.0 else (0.65 if temporal_delta <= 12.0 else 0.15)
        if node_intervals:
            temporal_similarity = max(
                temporal_similarity,
                self._sequence_similarity(node_intervals[-6:], [node_intervals[-1]], 400.0) if len(node_intervals) > 1 else temporal_similarity,
            )
        rssi_similarity = 0.0
        if features.get("rssi") is not None and node_rssi:
            try:
                delta = abs(float(features["rssi"]) - (sum(node_rssi) / len(node_rssi)))
                rssi_similarity = max(0.0, 1.0 - min(1.0, delta / 20.0))
            except Exception:
                rssi_similarity = 0.0
        payload_signature_match = 1.0 if str(features.get("payload_signature_hash") or "") in set(node.get("payload_signatures") or []) else 0.0
        service_uuid_overlap = self._jaccard_similarity(features.get("service_uuids") or [], list(node.get("service_signature") or []))
        manufacturer_data_match = 1.0 if str(features.get("manufacturer_prefix") or "") and str(features.get("manufacturer_prefix") or "") == str(node.get("manufacturer_data_signature") or "") else 0.0
        company_id_match = 0.0
        try:
            if features.get("manufacturer_company_id") is not None and node.get("manufacturer_company_id") is not None and int(features.get("manufacturer_company_id")) == int(node.get("manufacturer_company_id")):
                company_id_match = 1.0
        except Exception:
            company_id_match = 0.0
        prefix_match = 0.0
        if str(features.get("address_type") or "") == "public" and str(node.get("address_type") or "") == "public":
            if str(features.get("public_prefix") or "") and str(features.get("public_prefix") or "") == str(node.get("public_prefix") or ""):
                prefix_match = 1.0
        spatial_proximity = rssi_similarity
        host_match = 0.0
        host_candidates = node.get("host_candidates") or []
        if host_candidates and str(features.get("name") or "") not in {"", "Unknown BLE Device"}:
            lowered_name = str(features.get("name") or "").strip().lower()
            if any(lowered_name and lowered_name in str(item.get("name") or "").strip().lower() for item in host_candidates if isinstance(item, dict)):
                host_match = 1.0

        score = (
            temporal_similarity * 0.25 +
            rssi_similarity * 0.20 +
            payload_signature_match * 0.20 +
            service_uuid_overlap * 0.15 +
            company_id_match * 0.12 +
            manufacturer_data_match * 0.10 +
            prefix_match * 0.08 +
            spatial_proximity * 0.10
        )
        evidence = {
            "temporal": round(temporal_similarity, 3),
            "rssi": round(rssi_similarity, 3),
            "payload": round(payload_signature_match, 3),
            "service": round(service_uuid_overlap, 3),
            "company_id": round(company_id_match, 3),
            "manufacturer": round(manufacturer_data_match, 3),
            "public_prefix": round(prefix_match, 3),
            "host_match": round(host_match, 3),
            "spatial_proximity": round(spatial_proximity, 3),
        }
        return {"score": round(min(1.0, score), 3), "evidence": evidence}

    def _new_identity_node(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_identity_features(observation)
        identity_id = f"idn-{sha1(f'{features.get('rf_address')}|{features.get('payload_signature_hash')}|{features.get('timestamp')}'.encode('utf-8')).hexdigest()[:14]}"
        rssi_value = []
        if features.get("rssi") is not None:
            try:
                rssi_value = [float(features["rssi"])]
            except Exception:
                rssi_value = []
        return {
            "id": identity_id,
            "rf_addresses": [str(features.get("rf_address") or "").lower()],
            "public_prefix": str(features.get("public_prefix") or ""),
            "address_type": str(features.get("address_type") or ""),
            "linked_asset_keys": [str(features.get("asset_key") or "").lower()] if str(features.get("asset_key") or "").strip() else [],
            "first_seen": float(features.get("timestamp") or time.time()),
            "last_seen": float(features.get("timestamp") or time.time()),
            "service_signature": list(features.get("service_uuids") or []),
            "manufacturer_company_id": features.get("manufacturer_company_id"),
            "manufacturer_data_signature": str(features.get("manufacturer_prefix") or ""),
            "adv_structure_signature": {
                "packet_lengths": [int(features.get("packet_length") or 0)] if int(features.get("packet_length") or 0) > 0 else [],
                "ad_structure_counts": [int(features.get("structure_count") or 0)] if int(features.get("structure_count") or 0) > 0 else [],
                "flags": [features.get("adv_flags")] if features.get("adv_flags") is not None else [],
            },
            "payload_signatures": [str(features.get("payload_signature_hash") or "")],
            "rssi_series": rssi_value,
            "rssi_variance": 0.0,
            "temporal_pattern": [],
            "host_candidates": [],
            "resolved_host": "",
            "validation_sessions": [],
            "session_history": [],
            "gatt_history": [],
            "state_history": [{"state": "passive", "timestamp": float(features.get("timestamp") or time.time())}],
            "confidence_score": 0.45,
            "evidence": {"bootstrap": 1.0},
            "ambiguity": False,
        }

    def _attach_observation_to_node(self, node: Dict[str, Any], observation: Dict[str, Any], score_result: Dict[str, Any] | None = None) -> None:
        features = self._extract_identity_features(observation)
        address = str(features.get("rf_address") or "").lower()
        if address and address not in node["rf_addresses"]:
            node["rf_addresses"].append(address)
        asset_key = str(features.get("asset_key") or "").lower()
        if asset_key and asset_key not in node.get("linked_asset_keys", []):
            node.setdefault("linked_asset_keys", []).append(asset_key)
        timestamp = float(features.get("timestamp") or time.time())
        if node.get("last_seen"):
            delta_ms = max(0.0, (timestamp - float(node.get("last_seen") or timestamp)) * 1000.0)
            if delta_ms > 0:
                node.setdefault("temporal_pattern", []).append(round(delta_ms, 3))
                node["temporal_pattern"] = list(node["temporal_pattern"])[-20:]
        node["first_seen"] = min(float(node.get("first_seen") or timestamp), timestamp)
        node["last_seen"] = max(float(node.get("last_seen") or timestamp), timestamp)
        for item in features.get("service_uuids") or []:
            if item not in node.get("service_signature", []):
                node.setdefault("service_signature", []).append(item)
        if str(features.get("manufacturer_prefix") or "") and not str(node.get("manufacturer_data_signature") or ""):
            node["manufacturer_data_signature"] = str(features.get("manufacturer_prefix") or "")
        if not node.get("manufacturer_company_id") and features.get("manufacturer_company_id") is not None:
            node["manufacturer_company_id"] = features.get("manufacturer_company_id")
        if not str(node.get("public_prefix") or "") and str(features.get("public_prefix") or ""):
            node["public_prefix"] = str(features.get("public_prefix") or "")
        if str(features.get("payload_signature_hash") or "") and str(features.get("payload_signature_hash") or "") not in node.get("payload_signatures", []):
            node.setdefault("payload_signatures", []).append(str(features.get("payload_signature_hash") or ""))
        if features.get("rssi") is not None:
            try:
                node.setdefault("rssi_series", []).append(float(features["rssi"]))
                node["rssi_series"] = list(node["rssi_series"])[-20:]
            except Exception:
                pass
        stats = self._rolling_stats([float(item) for item in (node.get("rssi_series") or []) if item is not None])
        node["rssi_variance"] = stats["variance"]
        adv_sig = node.setdefault("adv_structure_signature", {"packet_lengths": [], "ad_structure_counts": [], "flags": []})
        packet_length = int(features.get("packet_length") or 0)
        if packet_length > 0 and packet_length not in adv_sig["packet_lengths"]:
            adv_sig["packet_lengths"].append(packet_length)
        structure_count = int(features.get("structure_count") or 0)
        if structure_count > 0:
            adv_sig["ad_structure_counts"].append(structure_count)
            adv_sig["ad_structure_counts"] = adv_sig["ad_structure_counts"][-20:]
        if features.get("adv_flags") is not None and features.get("adv_flags") not in adv_sig["flags"]:
            adv_sig["flags"].append(features.get("adv_flags"))
        if score_result:
            node["confidence_score"] = max(float(node.get("confidence_score") or 0.0), float(score_result.get("score") or 0.0))
            node["evidence"] = dict(score_result.get("evidence") or {})

    def _node_to_node_match(self, current: Dict[str, Any], prior: Dict[str, Any]) -> float:
        temporal = self._sequence_similarity(list(current.get("temporal_pattern") or []), list(prior.get("temporal_pattern") or []), 400.0)
        current_mean = self._rolling_stats([float(item) for item in (current.get("rssi_series") or []) if item is not None])["mean"]
        prior_mean = self._rolling_stats([float(item) for item in (prior.get("rssi_series") or []) if item is not None])["mean"]
        rssi = 0.0
        if current_mean or prior_mean:
            rssi = max(0.0, 1.0 - min(1.0, abs(current_mean - prior_mean) / 20.0))
        payload = self._jaccard_similarity(list(current.get("payload_signatures") or []), list(prior.get("payload_signatures") or []))
        service = self._jaccard_similarity(list(current.get("service_signature") or []), list(prior.get("service_signature") or []))
        manufacturer = 1.0 if str(current.get("manufacturer_data_signature") or "") and str(current.get("manufacturer_data_signature") or "") == str(prior.get("manufacturer_data_signature") or "") else 0.0
        spatial = rssi
        return round(
            temporal * 0.25 +
            rssi * 0.20 +
            payload * 0.20 +
            service * 0.15 +
            manufacturer * 0.10 +
            spatial * 0.10,
            3,
        )

    def _bind_identity_hosts_and_sessions(self, nodes: List[Dict[str, Any]], devices: List[Dict[str, Any]]) -> None:
        task_map = self._task_state_map()
        for node in nodes:
            host_candidates: List[Dict[str, Any]] = []
            resolved_host = ""
            gatt_history: List[Dict[str, Any]] = []
            session_history: List[Dict[str, Any]] = []
            state_history = list(node.get("state_history") or [])
            for device in devices:
                addresses = {str(device.get("address") or "").lower(), *(str(item).lower() for item in (device.get("linked_addresses") or []) if str(item).strip())}
                if not set(node.get("rf_addresses") or []).intersection(addresses):
                    continue
                if device.get("resolution_host_path"):
                    host_candidates.append(
                        {
                            "path": str(device.get("resolution_host_path") or ""),
                            "address": str(device.get("resolution_host_address") or ""),
                            "name": str(device.get("name") or ""),
                            "confidence": float(device.get("resolution_confidence") or 0.0),
                            "method": str(device.get("resolution_method") or ""),
                        }
                    )
                if str(device.get("resolution_state") or "") in {"materialized", "validation_ready"} and float(device.get("resolution_confidence") or 0.0) >= 0.55:
                    resolved_host = str(device.get("resolution_host_path") or "")
                device_key = str(device.get("device_key") or "").strip().lower()
                task = task_map.get(device_key) or {}
                if isinstance(task.get("validation_suite"), dict) and task.get("validation_suite"):
                    session_history.append(
                        {
                            "identity_id": node.get("id"),
                            "host_device": str(device.get("resolution_host_path") or ""),
                            "trust_state": str(((device.get("active_validation") or {}).get("trust_state")) or "unknown"),
                            "timestamp": float(task.get("updated_at") or time.time()),
                            "device_key": device_key,
                            "workflow": str(task.get("workflow") or ""),
                        }
                    )
                if isinstance(task.get("gatt_test"), dict) and task.get("gatt_test"):
                    gatt = task.get("gatt_test") or {}
                    gatt_history.append(
                        {
                            "timestamp": float(gatt.get("tested_at") or task.get("updated_at") or time.time()),
                            "service_count": int(gatt.get("service_count") or 0),
                            "characteristic_count": int(gatt.get("characteristic_count") or 0),
                            "profile_hash": sha1(json.dumps({
                                "services": int(gatt.get("service_count") or 0),
                                "characteristics": int(gatt.get("characteristic_count") or 0),
                                "control_surfaces": len(gatt.get("control_surfaces") or []),
                            }, sort_keys=True).encode("utf-8")).hexdigest()[:16],
                        }
                    )
                active = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
                if active.get("attempted"):
                    state_history.append({"state": str(active.get("trust_state") or "connected_unpaired"), "timestamp": float(active.get("tested_at") or time.time())})
                    if bool((active.get("info") or {}).get("paired")):
                        state_history.append({"state": "paired", "timestamp": float(active.get("tested_at") or time.time())})
                    if bool((active.get("info") or {}).get("trusted")):
                        state_history.append({"state": "trusted", "timestamp": float(active.get("tested_at") or time.time())})
                    if str(((active.get("reconnect_probe") or {}).get("result")) or ""):
                        state_history.append({"state": "reconnect", "timestamp": float(active.get("tested_at") or time.time())})
            node["host_candidates"] = host_candidates[:8]
            node["resolved_host"] = resolved_host
            node["validation_sessions"] = session_history[:12]
            node["session_history"] = session_history[:12]
            node["gatt_history"] = sorted(gatt_history, key=lambda item: float(item.get("timestamp") or 0), reverse=True)[:12]
            node["state_history"] = sorted(state_history, key=lambda item: float(item.get("timestamp") or 0))

    def _build_identity_graph(self, devices: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        observations = sorted(self._read_jsonl(self.observation_log), key=lambda item: float(item.get("timestamp") or 0))
        previous = self._identity_graph_payload()
        previous_nodes = previous.get("nodes") if isinstance(previous.get("nodes"), list) else []
        nodes: List[Dict[str, Any]] = []
        stage_status = "idle"
        if observations:
            stage_status = "running"
        for observation in observations:
            best_index = -1
            best_score = 0.0
            best_evidence: Dict[str, Any] = {}
            for index, node in enumerate(nodes):
                score_result = self._observation_to_identity_score(observation, node)
                if float(score_result.get("score") or 0.0) > best_score:
                    best_score = float(score_result.get("score") or 0.0)
                    best_index = index
                    best_evidence = score_result
            if best_index >= 0 and best_score >= 0.56:
                self._attach_observation_to_node(nodes[best_index], observation, best_evidence)
                nodes[best_index]["ambiguity"] = bool(0.56 <= best_score < 0.68)
            else:
                nodes.append(self._new_identity_node(observation))

        for node in nodes:
            reuse_id = ""
            reuse_score = 0.0
            for prior in previous_nodes:
                if not isinstance(prior, dict):
                    continue
                match_score = self._node_to_node_match(node, prior)
                if match_score > reuse_score:
                    reuse_score = match_score
                    reuse_id = str(prior.get("id") or "")
            if reuse_id and reuse_score >= 0.58:
                node["id"] = reuse_id
                node["confidence_score"] = max(float(node.get("confidence_score") or 0.0), reuse_score)

        binding_devices = devices if devices is not None else []
        self._bind_identity_hosts_and_sessions(nodes, binding_devices)
        correlated_nodes = sum(1 for node in nodes if len(node.get("rf_addresses") or []) > 1)
        resolved_hosts = sum(1 for node in nodes if str(node.get("resolved_host") or "").strip())
        payload = {
            "nodes": nodes,
            "updated_at": time.time(),
            "summary": {
                "node_count": len(nodes),
                "correlated_nodes": correlated_nodes,
                "resolved_hosts": resolved_hosts,
            },
        }
        self.identity_engine_state = {
            "status": "completed" if observations else "idle",
            "summary": f"{len(nodes)} identity node(s) · {correlated_nodes} correlated · {resolved_hosts} host-bound",
            "stages": [
                {"id": "features", "label": "Features", "state": "completed" if observations else "idle", "detail": f"{len(observations)} observations normalized", "percent": 100 if observations else 0},
                {"id": "correlate", "label": "Correlate", "state": "completed" if nodes else "idle", "detail": f"{correlated_nodes} multi-address identities", "percent": 100 if nodes else 0},
                {"id": "host", "label": "Host Bind", "state": "completed" if resolved_hosts else ("weak" if nodes else "idle"), "detail": f"{resolved_hosts} resolved host object(s)", "percent": 100 if resolved_hosts else (44 if nodes else 0)},
                {"id": "sessions", "label": "Sessions", "state": "completed" if any(node.get('validation_sessions') for node in nodes) else ("weak" if nodes else "idle"), "detail": f"{sum(len(node.get('validation_sessions') or []) for node in nodes)} validation session refs", "percent": 100 if any(node.get('validation_sessions') for node in nodes) else (36 if nodes else 0)},
                {"id": "state", "label": "State", "state": "completed" if any(node.get('gatt_history') or node.get('state_history') for node in nodes) else ("weak" if nodes else "idle"), "detail": f"{sum(len(node.get('gatt_history') or []) for node in nodes)} GATT snapshots", "percent": 100 if any(node.get('gatt_history') for node in nodes) else (40 if nodes else 0)},
            ],
            "node_count": len(nodes),
            "resolved_hosts": resolved_hosts,
            "correlated_nodes": correlated_nodes,
            "updated_at": time.time(),
        }
        if observations or nodes:
            self._save_identity_graph_payload(payload)
        return payload

    def _parse_dbus_scalar(self, raw: str) -> Any:
        text = str(raw or "").strip()
        if text.startswith('string "'):
            return text.split('"', 1)[1].rsplit('"', 1)[0]
        if text.startswith('object path "'):
            return text.split('"', 1)[1].rsplit('"', 1)[0]
        if text.startswith("boolean "):
            return text.split(None, 1)[1].strip().lower() == "true"
        if text.startswith(("byte ", "uint16 ", "uint32 ", "int16 ", "int32 ")):
            try:
                return int(text.split(None, 1)[1].strip())
            except Exception:
                return text
        return text

    def _parse_dbus_getall_output(self, output: str) -> Dict[str, Any]:
        props: Dict[str, Any] = {}
        lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
        idx = 0
        current_key = ""
        while idx < len(lines):
            line = lines[idx]
            if not current_key and line.startswith('string "'):
                current_key = line.split('"', 1)[1].rsplit('"', 1)[0]
                idx += 1
                continue
            if current_key and line.startswith("variant"):
                rest = line[len("variant") :].strip()
                if rest.startswith("array"):
                    values: List[Any] = []
                    idx += 1
                    while idx < len(lines):
                        item_line = lines[idx]
                        if item_line.startswith("]"):
                            break
                        if item_line.startswith(("string ", "object path ", "boolean ", "byte ", "uint16 ", "uint32 ", "int16 ", "int32 ")):
                            values.append(self._parse_dbus_scalar(item_line))
                        idx += 1
                    props[current_key] = values
                    current_key = ""
                else:
                    props[current_key] = self._parse_dbus_scalar(rest)
                    current_key = ""
            idx += 1
        return props

    def _extract_dbus_xml(self, output: str) -> str:
        text = str(output or "")
        match = re.search(r'string "(.*)"\s*$', text, re.DOTALL)
        if not match:
            return ""
        xml_blob = match.group(1)
        xml_blob = xml_blob.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")
        return html.unescape(xml_blob)

    def _bluez_dbus_call(self, path: str, interface: str, member: str, args: list[str] | None = None, timeout: float = 12.0) -> Dict[str, Any]:
        cmd = [
            "dbus-send",
            "--system",
            "--print-reply",
            "--dest=org.bluez",
            path,
            f"{interface}.{member}",
        ]
        if args:
            cmd.extend(args)
        return self._run_capture_command(cmd, timeout=timeout)

    def _bluez_managed_objects_output(self, timeout: float = 8.0) -> str:
        result = self._bluez_dbus_call(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects",
            timeout=timeout,
        )
        return result.get("stdout") or result.get("stderr") or ""

    def _bluez_find_device_path(self, address: str, timeout: float = 8.0) -> str:
        target = str(address or "").strip().upper()
        if not target:
            return ""
        output = self._bluez_managed_objects_output(timeout=timeout)
        if not output:
            return ""
        current_path = ""
        current_is_device = False
        expect_address_value = False
        for raw in output.splitlines():
            line = raw.strip()
            if line.startswith('object path "'):
                current_path = line.split('"', 1)[1].rsplit('"', 1)[0]
                current_is_device = False
                expect_address_value = False
                continue
            if line == 'string "org.bluez.Device1"':
                current_is_device = True
                continue
            if current_is_device and line == 'string "Address"':
                expect_address_value = True
                continue
            if expect_address_value and line.startswith("variant"):
                continue
            if expect_address_value and line.startswith('string "'):
                observed = line.split('"', 1)[1].rsplit('"', 1)[0].strip().upper()
                if observed == target:
                    return current_path
                expect_address_value = False
        return ""

    def _bluez_adapter_path(self, timeout: float = 6.0) -> str:
        payload = self._bluez_managed_objects_json(timeout=timeout)
        data = payload.get("data")
        if not isinstance(data, list) or not data:
            return "/org/bluez/hci0"
        objects = self._unwrap_busctl_variant(data[0])
        if not isinstance(objects, dict):
            return "/org/bluez/hci0"
        powered_path = ""
        fallback_path = ""
        for path, interfaces in objects.items():
            if not isinstance(interfaces, dict):
                continue
            props = interfaces.get("org.bluez.Adapter1")
            if not isinstance(props, dict):
                continue
            fallback_path = str(path)
            if bool(props.get("Powered")):
                powered_path = str(path)
                if bool(props.get("Pairable")) or bool(props.get("Discoverable")) or bool(props.get("Discovering")):
                    return str(path)
        return powered_path or fallback_path or "/org/bluez/hci0"

    def _bluez_device_candidates(self, timeout: float = 6.0) -> List[Dict[str, Any]]:
        payload = self._bluez_managed_objects_json(timeout=timeout)
        data = payload.get("data")
        if not isinstance(data, list) or not data:
            return []
        objects = self._unwrap_busctl_variant(data[0])
        if not isinstance(objects, dict):
            return []
        candidates: List[Dict[str, Any]] = []
        for path, interfaces in objects.items():
            if not isinstance(interfaces, dict):
                continue
            props = interfaces.get("org.bluez.Device1")
            if not isinstance(props, dict):
                continue
            manufacturer_data = props.get("ManufacturerData")
            manufacturer_company_id = None
            manufacturer_keys: List[str] = []
            if isinstance(manufacturer_data, dict):
                manufacturer_keys = sorted(str(key) for key in manufacturer_data.keys())
                if manufacturer_keys:
                    try:
                        manufacturer_company_id = int(manufacturer_keys[0], 0)
                    except Exception:
                        manufacturer_company_id = None
            rssi = props.get("RSSI")
            try:
                rssi_value = int(rssi) if rssi is not None else None
            except Exception:
                rssi_value = None
            primary_name = str(props.get("Name") or "").strip()
            alias = str(props.get("Alias") or "").strip()
            display_name = primary_name or alias
            if self._looks_like_address_label(display_name) and alias and not self._looks_like_address_label(alias):
                display_name = alias
            candidates.append(
                {
                    "path": str(path),
                    "address": str(props.get("Address") or "").upper(),
                    "address_type": str(props.get("AddressType") or "").lower(),
                    "name": display_name,
                    "alias": alias,
                    "uuids": sorted(str(item).lower() for item in (props.get("UUIDs") or []) if str(item).strip()),
                    "rssi": rssi_value,
                    "paired": bool(props.get("Paired")),
                    "trusted": bool(props.get("Trusted")),
                    "connected": bool(props.get("Connected")),
                    "services_resolved": bool(props.get("ServicesResolved")),
                    "manufacturer_company_id": manufacturer_company_id,
                    "manufacturer_keys": manufacturer_keys,
                    "raw": props,
                }
            )
        return candidates

    def _looks_like_address_label(self, value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        normalized = text.replace("-", ":").lower()
        parts = normalized.split(":")
        if len(parts) != 6:
            return False
        return all(len(part) == 2 and all(ch in "0123456789abcdef" for ch in part) for part in parts)

    def _preferred_resolution_name(self, candidate: Dict[str, Any]) -> str:
        name = str(candidate.get("name") or "").strip()
        alias = str(candidate.get("alias") or "").strip()
        if name and not self._looks_like_address_label(name):
            return name
        if alias and not self._looks_like_address_label(alias):
            return alias
        return name or alias

    def _bluez_set_discovery_filter(self, filter_spec: Dict[str, Any]) -> Dict[str, Any]:
        adapter_path = self._bluez_adapter_path()
        if self._bluez_gio_available():
            variant_map: Dict[str, Any] = {}
            transport = str(filter_spec.get("Transport") or "le").strip()
            if transport:
                variant_map["Transport"] = GLib.Variant("s", transport)
            duplicate = filter_spec.get("DuplicateData")
            if duplicate is not None:
                variant_map["DuplicateData"] = GLib.Variant("b", bool(duplicate))
            pattern = str(filter_spec.get("Pattern") or "").strip()
            if pattern:
                variant_map["Pattern"] = GLib.Variant("s", pattern)
            rssi = filter_spec.get("RSSI")
            if rssi is not None:
                try:
                    variant_map["RSSI"] = GLib.Variant("n", int(rssi))
                except Exception:
                    pass
            uuids = [str(item).strip().lower() for item in (filter_spec.get("UUIDs") or []) if str(item).strip()]
            if uuids:
                variant_map["UUIDs"] = GLib.Variant("as", uuids)
            params = GLib.Variant("(a{sv})", (variant_map,))
            return self._bluez_gio_call(adapter_path, "org.bluez.Adapter1", "SetDiscoveryFilter", parameters=params, timeout=8.0)
        entries: List[str] = []
        transport = str(filter_spec.get("Transport") or "le").strip()
        if transport:
            entries.extend(["Transport", "s", transport])
        duplicate = filter_spec.get("DuplicateData")
        if duplicate is not None:
            entries.extend(["DuplicateData", "b", "true" if bool(duplicate) else "false"])
        pattern = str(filter_spec.get("Pattern") or "").strip()
        if pattern:
            entries.extend(["Pattern", "s", pattern])
        rssi = filter_spec.get("RSSI")
        if rssi is not None:
            try:
                entries.extend(["RSSI", "n", "--", str(int(rssi))])
            except Exception:
                pass
        uuids = [str(item).strip().lower() for item in (filter_spec.get("UUIDs") or []) if str(item).strip()]
        if uuids:
            entries.extend(["UUIDs", "as", str(len(uuids)), *uuids])
        entry_count = 0
        idx = 0
        while idx < len(entries):
            entry_count += 1
            key = entries[idx]
            kind = entries[idx + 1] if idx + 1 < len(entries) else ""
            idx += 2
            if kind == "as":
                count = int(entries[idx]) if idx < len(entries) else 0
                idx += 1 + count
            elif kind == "n" and idx < len(entries) and entries[idx] == "--":
                idx += 2
            else:
                idx += 1
        return self._bluez_busctl_json_call(
            adapter_path,
            "org.bluez.Adapter1",
            "SetDiscoveryFilter",
            "a{sv}",
            [str(entry_count), *entries],
            timeout=8.0,
        )

    def _resolution_filter_for_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        address = str(device.get("address") or "").strip().upper()
        name = str(device.get("name") or "").strip()
        pattern = ""
        if address and str(device.get("address_type") or "").lower() == "public":
            pattern = address
        elif name and name != "Unknown BLE Device":
            pattern = name[:12]
        elif address:
            pattern = ":".join(address.split(":")[:5])
        avg_rssi = device.get("avg_rssi")
        rssi_threshold = None
        if avg_rssi is not None:
            try:
                rssi_threshold = max(-95, min(-35, int(float(avg_rssi)) - 12))
            except Exception:
                rssi_threshold = None
        return {
            "Transport": "le",
            "DuplicateData": True,
            "Pattern": pattern,
            "RSSI": rssi_threshold,
            "UUIDs": list(device.get("service_uuids") or [])[:8],
        }

    def _bluez_start_discovery_session(self, filter_spec: Dict[str, Any]) -> Dict[str, Any]:
        adapter_path = self._bluez_adapter_path()
        set_filter = self._bluez_set_discovery_filter(filter_spec)
        if not set_filter.get("ok"):
            return {"ok": False, "detail": set_filter.get("detail") or "unable to set discovery filter", "error": set_filter.get("error") or "set_filter_failed"}
        if self._bluez_gio_available():
            return self._bluez_gio_call(adapter_path, "org.bluez.Adapter1", "StartDiscovery", timeout=8.0)
        return self._bluez_dbus_call(adapter_path, "org.bluez.Adapter1", "StartDiscovery", timeout=8.0)

    def _bluez_stop_discovery_session(self) -> Dict[str, Any]:
        adapter_path = self._bluez_adapter_path()
        if self._bluez_gio_available():
            return self._bluez_gio_call(adapter_path, "org.bluez.Adapter1", "StopDiscovery", timeout=8.0)
        return self._bluez_dbus_call(adapter_path, "org.bluez.Adapter1", "StopDiscovery", timeout=8.0)

    def _resolution_candidate_score(self, device: Dict[str, Any], candidate: Dict[str, Any], resolution_started_at: float, burst_seconds: float) -> Dict[str, Any]:
        rf_address = str(device.get("address") or "").strip().upper()
        rf_type = str(device.get("address_type") or "").strip().lower()
        rf_name = str(device.get("name") or "").strip().lower()
        rf_uuids = {str(item).lower() for item in (device.get("service_uuids") or [])}
        rf_company_id = device.get("manufacturer_company_id")
        rf_rssi = device.get("avg_rssi")

        host_address = str(candidate.get("address") or "").strip().upper()
        host_type = str(candidate.get("address_type") or "").strip().lower()
        host_name = str(candidate.get("name") or candidate.get("alias") or "").strip().lower()
        host_uuids = {str(item).lower() for item in (candidate.get("uuids") or [])}
        host_company_id = candidate.get("manufacturer_company_id")
        host_rssi = candidate.get("rssi")

        score = 0.0
        evidence: List[str] = []
        method = "timing_correlation"

        if rf_address and host_address and rf_address == host_address:
            score += 0.55
            method = "direct_address"
            evidence.append("address_match")
            if rf_type and host_type and rf_type == host_type:
                score += 0.05
                evidence.append("address_type_match")
        elif rf_address and host_address and rf_address.split(":")[:5] == host_address.split(":")[:5]:
            score += 0.16
            evidence.append("address_prefix_match")
        elif rf_address and host_address:
            rf_parts = rf_address.split(":")
            host_parts = host_address.split(":")
            if len(rf_parts) == 6 and len(host_parts) == 6:
                matching_octets = sum(1 for left, right in zip(rf_parts, host_parts) if left == right)
                if matching_octets >= 5:
                    score += 0.30
                    if method != "direct_address":
                        method = "near_address"
                    evidence.append("near_address_match")
                elif matching_octets >= 4:
                    score += 0.12
                    evidence.append("partial_address_match")

        if rf_company_id is not None and host_company_id is not None and int(rf_company_id) == int(host_company_id):
            score += 0.14
            if method != "direct_address":
                method = "manufacturer_signature"
            evidence.append("manufacturer_match")

        if rf_uuids and host_uuids:
            overlap = len(rf_uuids.intersection(host_uuids))
            if overlap:
                score += min(0.18, 0.07 * overlap)
                if method not in {"direct_address", "manufacturer_signature"}:
                    method = "uuid_signature"
                evidence.append(f"uuid_overlap:{overlap}")

        if rf_name and rf_name != "unknown ble device" and host_name:
            if rf_name == host_name:
                score += 0.10
                evidence.append("name_exact")
            elif rf_name in host_name or host_name in rf_name:
                score += 0.07
                evidence.append("name_similarity")

        if rf_rssi is not None and host_rssi is not None:
            try:
                delta = abs(float(rf_rssi) - float(host_rssi))
                if delta <= 6:
                    score += 0.08
                    evidence.append("rssi_close")
                elif delta <= 12:
                    score += 0.04
                    evidence.append("rssi_partial")
            except Exception:
                pass

        last_seen_delta = max(0.0, time.time() - float(device.get("last_seen") or time.time()))
        if last_seen_delta <= max(12.0, burst_seconds * 2):
            score += 0.05
            evidence.append("recent_rf_seen")
        if time.monotonic() - resolution_started_at <= burst_seconds + 0.8:
            score += 0.03
            evidence.append("timing_correlation")

        return {
            "score": round(min(1.0, score), 3),
            "method": method,
            "evidence": evidence,
        }

    def _confidence_label(self, score: float) -> str:
        value = float(score or 0.0)
        if value >= 0.9:
            return "verified"
        if value >= 0.72:
            return "high confidence"
        if value >= 0.56:
            return "moderate confidence"
        if value >= 0.34:
            return "partial match"
        if value > 0:
            return "weak signal"
        return "unknown"

    def _blocked_state_detail(
        self,
        *,
        code: str,
        stage: str,
        reason: str,
        evidence: List[str] | None = None,
        next_action: str = "",
    ) -> Dict[str, Any]:
        return {
            "code": str(code or "unknown"),
            "stage": str(stage or "unknown"),
            "reason": str(reason or "unknown"),
            "evidence": [str(item) for item in (evidence or []) if str(item).strip()],
            "next_action": str(next_action or "").strip(),
            "label": str(code or "unknown").replace("_", " "),
        }

    def _resolve_target_materialization(self, device: Dict[str, Any], force_retry: bool = False) -> Dict[str, Any]:
        device_key = str(device.get("device_key") or "").strip().lower()
        now = time.time()
        gate = self._auditability_gate(device)
        freshness_seconds = max(0.0, now - float(device.get("last_seen") or now))
        cached = self._cached_resolution(device_key)
        if cached and not force_retry:
            cached_age = now - float(cached.get("updated_at") or 0)
            state = str(cached.get("state") or "").upper()
            blocked_code = str(((cached.get("blocked_state") or {}).get("code")) or "").strip().lower()
            transient_failure = blocked_code in {
                "host_unavailable",
                "service_unregistered",
                "system_bus_unavailable",
                "adapter_missing",
                "adapter_unpowered",
                "discovery_start_failed",
                "no_host_candidate",
                "candidate_only_not_materialized",
            }
            if cached_age <= 45 and state in {"MATERIALIZED", "VALIDATION_READY", "CANDIDATE"}:
                return dict(cached)
            if cached_age <= 20 and state == "FAILED" and not transient_failure:
                return dict(cached)

        result: Dict[str, Any] = {
            "device_key": device_key,
            "state": "OBSERVED",
            "materialization_status": "failed",
            "resolution_confidence": 0.0,
            "resolution_method": "",
            "ambiguity": False,
            "host_candidate_count": 0,
            "host_path": "",
            "host_address": "",
            "matched_name": "",
            "score_breakdown": [],
            "detail": "rf observation retained without host-side candidate",
            "failure_reason": "",
            "next_action": "",
            "retry_count": 0,
            "updated_at": now,
            "last_success_timestamp": float(cached.get("last_success_timestamp") or 0),
            "freshness_seconds": round(freshness_seconds, 1),
            "blocked_state": self._blocked_state_detail(
                code="rf_visible_only",
                stage="materialization",
                reason="RF observation retained without host-side candidate evidence.",
                evidence=[
                    f"last_seen={round(freshness_seconds, 1)}s ago",
                    f"rf_quality={str((gate.get('rf_quality') or {}).get('label') or 'WEAK')}",
                ],
                next_action="Keep the target active and retry while advertisements are fresh.",
            ),
        }
        host_readiness = self._bluez_host_readiness()
        if not bool(host_readiness.get("ready")):
            host_state = str(host_readiness.get("state") or "host_unavailable")
            host_detail = str(host_readiness.get("detail") or "BlueZ host path unavailable on host")
            host_next_action = str(host_readiness.get("next_action") or "Repair the host Bluetooth stack before active validation.")
            evidence = []
            runtime = host_readiness.get("runtime") if isinstance(host_readiness.get("runtime"), dict) else {}
            if runtime:
                evidence.append(f"system_bus_ready={bool(runtime.get('system_bus_ready'))}")
                evidence.append(f"service_registered={bool(runtime.get('service_registered'))}")
            evidence.append(f"adapter_count={int(host_readiness.get('adapter_count') or 0)}")
            evidence.append(f"powered_adapters={int(host_readiness.get('powered_adapter_count') or 0)}")
            result["detail"] = host_detail
            result["failure_reason"] = host_detail
            result["next_action"] = host_next_action
            result["state"] = "FAILED"
            result["blocked_state"] = self._blocked_state_detail(
                code=host_state,
                stage="materialization",
                reason=host_detail,
                evidence=evidence,
                next_action=host_next_action,
            )
            self._cache_resolution(device_key, result)
            return result
        if gate["state"] == "NOT_AUDITABLE":
            result["detail"] = gate["reason"]
            result["failure_reason"] = gate["reason"]
            result["next_action"] = gate["action"]
            result["state"] = "FAILED"
            result["blocked_state"] = self._blocked_state_detail(
                code="not_auditable",
                stage="auditability",
                reason=gate["reason"],
                evidence=list((gate.get("rf_quality") or {}).get("reasons") or []),
                next_action=gate["action"],
            )
            self._cache_resolution(device_key, result)
            return result
        if not bool(device.get("connectable")):
            result["detail"] = "device advertised as non-connectable; host materialization skipped"
            result["failure_reason"] = result["detail"]
            result["next_action"] = "Retain passive evidence only."
            result["state"] = "FAILED"
            result["blocked_state"] = self._blocked_state_detail(
                code="nonconnectable_target",
                stage="materialization",
                reason=result["detail"],
                evidence=["connectable=false"],
                next_action=result["next_action"],
            )
            self._cache_resolution(device_key, result)
            return result

        filter_spec = self._resolution_filter_for_device(device)
        pass_count = 1
        if freshness_seconds <= 10:
            pass_count += 1
        if gate["state"] == "AUDITABLE" and str((gate.get("rf_quality") or {}).get("label") or "") == "STRONG":
            pass_count += 1
        if force_retry:
            pass_count = max(pass_count, 2)
        pass_count = min(pass_count, 3)

        best: Dict[str, Any] | None = None
        second: Dict[str, Any] | None = None
        best_scores: List[Dict[str, Any]] = []
        for attempt in range(pass_count):
            burst_seconds = 2.4 if freshness_seconds <= 8 else (3.2 if freshness_seconds <= 25 else 4.6)
            resolution_started_at = time.monotonic()
            started = self._bluez_start_discovery_session(filter_spec)
            if not started.get("ok"):
                result["detail"] = str(started.get("detail") or "unable to start discovery session")
                result["failure_reason"] = result["detail"]
                result["next_action"] = "Retry after confirming BlueZ discovery is working."
                result["state"] = "FAILED"
                result["blocked_state"] = self._blocked_state_detail(
                    code="discovery_start_failed",
                    stage="materialization",
                    reason=result["detail"],
                    evidence=[str(started.get("error") or "set_filter_failed")],
                    next_action=result["next_action"],
                )
                self._cache_resolution(device_key, result)
                return result
            try:
                time.sleep(burst_seconds)
            finally:
                self._bluez_stop_discovery_session()

            candidates = self._bluez_device_candidates(timeout=6.0)
            scores: List[Dict[str, Any]] = []
            for candidate in candidates:
                breakdown = self._resolution_candidate_score(device, candidate, resolution_started_at, burst_seconds)
                if breakdown["score"] <= 0:
                    continue
                scores.append({**breakdown, "candidate": candidate})
            scores.sort(key=lambda item: float(item.get("score") or 0), reverse=True)
            if scores and (best is None or float(scores[0].get("score") or 0.0) > float(best.get("score") or 0.0)):
                best = scores[0]
                second = scores[1] if len(scores) > 1 else None
                best_scores = scores
            if best and float(best.get("score") or 0.0) >= 0.72:
                break

        result["retry_count"] = max(0, pass_count - 1)
        result["host_candidate_count"] = len(best_scores)
        result["host_readiness"] = {
            "state": str(host_readiness.get("state") or "unknown"),
            "adapter_count": int(host_readiness.get("adapter_count") or 0),
            "powered_adapter_count": int(host_readiness.get("powered_adapter_count") or 0),
        }
        result["score_breakdown"] = [
            {
                "address": item["candidate"].get("address"),
                "name": item["candidate"].get("name"),
                "score": item.get("score"),
                "method": item.get("method"),
                "evidence": item.get("evidence"),
            }
            for item in best_scores[:4]
        ]

        if not best:
            result["detail"] = "no BlueZ Device1 candidates matched recent RF-guided discovery"
            result["failure_reason"] = result["detail"]
            result["next_action"] = "Keep the target active, move closer, and retry while advertisements are fresh."
            result["state"] = "FAILED"
            result["blocked_state"] = self._blocked_state_detail(
                code="no_host_candidate",
                stage="materialization",
                reason=result["detail"],
                evidence=[
                    f"pattern={str(filter_spec.get('Pattern') or '') or 'none'}",
                    f"uuid_count={len(filter_spec.get('UUIDs') or [])}",
                    f"freshness_seconds={result['freshness_seconds']}",
                ],
                next_action=result["next_action"],
            )
            self._cache_resolution(device_key, result)
            return result

        best_candidate = best["candidate"]
        result["resolution_confidence"] = float(best.get("score") or 0.0)
        result["resolution_method"] = str(best.get("method") or "")
        result["ambiguity"] = bool(second and abs(float(best.get("score") or 0) - float(second.get("score") or 0)) < 0.08)
        result["host_path"] = str(best_candidate.get("path") or "")
        result["host_address"] = str(best_candidate.get("address") or "")
        result["matched_name"] = self._preferred_resolution_name(best_candidate)
        result["resolution_label"] = self._confidence_label(result["resolution_confidence"])
        if result["resolution_confidence"] >= 0.72:
            result["state"] = "VALIDATION_READY" if bool(device.get("connectable")) else "MATERIALIZED"
            result["materialization_status"] = "materialized_after_retry" if pass_count > 1 else "materialized"
            result["last_success_timestamp"] = now
            retry_suffix = " after RF-aware retry" if pass_count > 1 else ""
            result["detail"] = f"{result['resolution_method']} matched BlueZ target with confidence {result['resolution_confidence']:.2f}{retry_suffix}"
            result["next_action"] = "Proceed with active BLE validation."
            result["blocked_state"] = {}
        else:
            result["state"] = "CANDIDATE"
            result["materialization_status"] = "candidate_only"
            result["detail"] = f"candidate materialized with confidence {result['resolution_confidence']:.2f}"
            result["failure_reason"] = "BlueZ saw a candidate, but identity confidence is still too weak for reliable auditing"
            result["next_action"] = "Rescan while the target is active and retry materialization immediately."
            result["blocked_state"] = self._blocked_state_detail(
                code="candidate_only_not_materialized",
                stage="materialization",
                reason=result["failure_reason"],
                evidence=[
                    f"candidate={result['host_address'] or result['matched_name'] or 'unknown'}",
                    f"confidence={result['resolution_confidence']:.2f}",
                    f"method={result['resolution_method'] or 'timing_correlation'}",
                ],
                next_action=result["next_action"],
            )
        result["updated_at"] = now
        self._cache_resolution(device_key, result)
        return result

    def _bluez_discovery_bootstrap(self, address: str, timeout: float = 6.0) -> Dict[str, Any]:
        target = str(address or "").strip().upper()
        if not target:
            return {"ok": False, "error": "no_address", "path": "", "detail": "no target address provided"}
        existing_path = self._bluez_find_device_path(target, timeout=4.0)
        if existing_path:
            return {"ok": True, "path": existing_path, "detail": "device object already present"}
        start = self._bluez_start_discovery_session({"Transport": "le", "DuplicateData": True, "Pattern": target})
        started = time.monotonic()
        materialized_path = ""
        while time.monotonic() - started < max(1.0, timeout):
            time.sleep(0.6)
            materialized_path = self._bluez_find_device_path(target, timeout=4.0)
            if materialized_path:
                break
        stop = self._bluez_stop_discovery_session()
        detail_parts = []
        for item in (start.get("stdout") or start.get("stderr") or "", stop.get("stdout") or stop.get("stderr") or ""):
            cleaned = str(item).strip()
            if cleaned:
                detail_parts.append(cleaned)
        if materialized_path:
            return {
                "ok": True,
                "path": materialized_path,
                "detail": "device object materialized after discovery bootstrap",
                "raw_output": "\n".join(detail_parts),
            }
        return {
            "ok": False,
            "error": "device_not_materialized",
            "path": "",
            "detail": "target did not appear as a BlueZ Device1 object during controller discovery",
            "raw_output": "\n".join(detail_parts),
        }

    def _aggregate_device_by_address(self, address: str) -> Dict[str, Any]:
        target = str(address or "").strip().lower()
        if not target:
            return {}
        for device in self._aggregate_devices():
            if str(device.get("address") or "").strip().lower() == target:
                return device
        return {}

    def _bluez_get_all(self, path: str, interface: str, timeout: float = 8.0) -> Dict[str, Any]:
        result = self._bluez_dbus_call(
            path,
            "org.freedesktop.DBus.Properties",
            "GetAll",
            [f"string:{interface}"],
            timeout=timeout,
        )
        payload = self._parse_dbus_getall_output(result.get("stdout") or result.get("stderr") or "")
        return payload if isinstance(payload, dict) else {}

    def _bluez_introspect_children(self, path: str, timeout: float = 8.0) -> List[str]:
        result = self._bluez_dbus_call(path, "org.freedesktop.DBus.Introspectable", "Introspect", timeout=timeout)
        xml_blob = self._extract_dbus_xml(result.get("stdout") or result.get("stderr") or "")
        if not xml_blob:
            return []
        try:
            root = ET.fromstring(xml_blob)
        except Exception:
            return []
        children: List[str] = []
        for node in root.findall("node"):
            name = str(node.attrib.get("name") or "").strip()
            if not name:
                continue
            children.append(f"{path}/{name}")
        return children

    def _bluez_fetch_device_info(self, address: str, path: str = "") -> Dict[str, Any]:
        if not self._bluez_dbus_available():
            return {
                "name": "",
                "alias": "",
                "paired": None,
                "trusted": None,
                "connected": None,
                "blocked": None,
                "legacy_pairing": None,
                "services_resolved": None,
                "uuids": [],
            }
        device_path = str(path or "").strip() or self._bluez_find_device_path(address) or self._bluez_device_path(address)
        props = self._bluez_get_all(device_path, "org.bluez.Device1")
        uuids = sorted({str(item).strip() for item in (props.get("UUIDs") or []) if str(item).strip()})
        name = str(props.get("Name") or "").strip()
        alias = str(props.get("Alias") or "").strip()
        if self._looks_like_address_label(name) and alias and not self._looks_like_address_label(alias):
            name = alias
        return {
            "name": name,
            "alias": alias,
            "paired": props.get("Paired"),
            "trusted": props.get("Trusted"),
            "connected": props.get("Connected"),
            "blocked": props.get("Blocked"),
            "legacy_pairing": props.get("LegacyPairing"),
            "services_resolved": props.get("ServicesResolved"),
            "uuids": uuids,
        }

    def _bluez_set_trusted(self, path: str, trusted: bool) -> Dict[str, Any]:
        return self._bluez_dbus_call(
            path,
            "org.freedesktop.DBus.Properties",
            "Set",
            [
                "string:org.bluez.Device1",
                "string:Trusted",
                f"variant:boolean:{'true' if trusted else 'false'}",
            ],
            timeout=8.0,
        )

    def _claim_device_operation(self, device_key: str, operation: str) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        now = time.time()
        lock_path = self.operation_lock_dir / f"{re.sub(r'[^a-z0-9._-]+', '_', normalized_key)}.lock"
        stale_owner: Dict[str, Any] = {}
        if lock_path.exists():
            try:
                stale_owner = json.loads(lock_path.read_text(encoding="utf-8"))
            except Exception:
                stale_owner = {}
            if now - float(stale_owner.get("started_at") or 0) > 90:
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass
        owner = {
            "device_key": normalized_key,
            "operation": operation,
            "status": "running",
            "started_at": now,
        }
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(owner, handle)
        except FileExistsError:
            return {
                "ok": False,
                "error": "device_busy",
                "detail": f"{stale_owner.get('operation') or 'operation'} already running on target",
                "owner": stale_owner,
            }
        with self._device_operation_lock:
            existing = self._device_operations.get(normalized_key)
            if existing and existing.get("status") == "running":
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass
                return {
                    "ok": False,
                    "error": "device_busy",
                    "detail": f"{existing.get('operation') or 'operation'} already running on target",
                    "owner": existing,
                }
            self._device_operations[normalized_key] = owner
            return {"ok": True, "owner": owner}

    def _release_device_operation(self, device_key: str, operation: str, status: str = "completed") -> None:
        normalized_key = str(device_key or "").strip().lower()
        lock_path = self.operation_lock_dir / f"{re.sub(r'[^a-z0-9._-]+', '_', normalized_key)}.lock"
        with self._device_operation_lock:
            existing = self._device_operations.get(normalized_key)
            if not existing:
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass
                return
            if str(existing.get("operation") or "") == str(operation or ""):
                existing["status"] = status
                existing["finished_at"] = time.time()
                self._device_operations.pop(normalized_key, None)
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            pass

    def _device_operation_state(self, device_key: str) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        with self._device_operation_lock:
            state = self._device_operations.get(normalized_key) or {}
            if state:
                return dict(state)
        lock_path = self.operation_lock_dir / f"{re.sub(r'[^a-z0-9._-]+', '_', normalized_key)}.lock"
        if lock_path.exists():
            try:
                return json.loads(lock_path.read_text(encoding="utf-8"))
            except Exception:
                return {"device_key": normalized_key, "operation": "running", "status": "running"}
        return {}

    def _target_session_lock_path(self, device_key: str) -> Path:
        normalized_key = str(device_key or "").strip().lower()
        return self.target_session_lock_dir / f"{re.sub(r'[^a-z0-9._-]+', '_', normalized_key)}.lock"

    def _claim_target_session(self, device_key: str, owner_id: str, purpose: str, wait_timeout: float = 20.0) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"ok": False, "error": "device_key_missing", "detail": "device key is required"}
        owner_token = str(owner_id or "").strip() or f"{purpose}:{threading.get_ident()}:{time.time():.6f}"
        lock_path = self._target_session_lock_path(normalized_key)
        deadline = time.monotonic() + max(0.5, wait_timeout)

        while True:
            stale_owner: Dict[str, Any] = {}
            if lock_path.exists():
                try:
                    stale_owner = json.loads(lock_path.read_text(encoding="utf-8"))
                except Exception:
                    stale_owner = {}
                if stale_owner.get("owner_id") == owner_token:
                    with self._target_session_lock:
                        current = self._target_sessions.get(normalized_key) or {}
                        current.update(stale_owner or {})
                        current["owner_id"] = owner_token
                        current["status"] = "running"
                        current["purpose"] = purpose
                        current["last_seen"] = time.time()
                        self._target_sessions[normalized_key] = current
                    return {"ok": True, "owner_id": owner_token, "reentrant": True}
                if time.time() - float(stale_owner.get("started_at") or 0) > 90:
                    try:
                        lock_path.unlink(missing_ok=True)
                    except Exception:
                        pass

            owner = {
                "device_key": normalized_key,
                "owner_id": owner_token,
                "purpose": purpose,
                "status": "running",
                "started_at": time.time(),
                "thread_id": threading.get_ident(),
            }
            try:
                fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(owner, handle)
                with self._target_session_lock:
                    self._target_sessions[normalized_key] = owner
                return {"ok": True, "owner_id": owner_token, "reentrant": False}
            except FileExistsError:
                if time.monotonic() >= deadline:
                    return {
                        "ok": False,
                        "error": "device_busy",
                        "detail": f"{stale_owner.get('purpose') or 'target session'} already running on target",
                        "owner": stale_owner,
                    }
                time.sleep(0.25)

    def _release_target_session(self, device_key: str, owner_id: str) -> None:
        normalized_key = str(device_key or "").strip().lower()
        lock_path = self._target_session_lock_path(normalized_key)
        with self._target_session_lock:
            current = self._target_sessions.get(normalized_key)
            if current and str(current.get("owner_id") or "") == str(owner_id or ""):
                self._target_sessions.pop(normalized_key, None)
        if lock_path.exists():
            try:
                payload = json.loads(lock_path.read_text(encoding="utf-8"))
            except Exception:
                payload = {}
            if not payload or str(payload.get("owner_id") or "") == str(owner_id or ""):
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass

    def _bluez_call_with_progress_wait(self, path: str, member: str, timeout: float = 10.0, settle_seconds: float = 3.5) -> Dict[str, Any]:
        result = self._bluez_dbus_call(path, "org.bluez.Device1", member, timeout=timeout)
        detail_blob = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}".lower()
        if "in progress" not in detail_blob and member.lower() != "connect":
            return result
        deadline = time.monotonic() + max(1.0, settle_seconds)
        observed_connected = False
        while time.monotonic() < deadline:
            info = self._bluez_fetch_device_info("", path=path)
            if member.lower() == "connect":
                if info.get("connected") is True or info.get("services_resolved") is True:
                    observed_connected = True
                    break
            else:
                if info.get("paired") is True or info.get("trusted") is True:
                    observed_connected = True
                    break
            time.sleep(0.35)
        if observed_connected:
            return {
                "ok": True,
                "returncode": 0,
                "stdout": result.get("stdout") or "",
                "stderr": result.get("stderr") or "",
            }
        return result

    def _bluez_wait_for_device_state(
        self,
        path: str,
        target_address: str,
        *,
        timeout: float = 8.0,
        require_connected: bool = False,
        require_services: bool = False,
    ) -> Dict[str, Any]:
        deadline = time.monotonic() + max(0.5, timeout)
        last_info: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            last_info = self._bluez_fetch_device_info(target_address, path=path)
            connected_ok = (not require_connected) or bool(last_info.get("connected"))
            services_ok = (not require_services) or bool(last_info.get("services_resolved"))
            if connected_ok and services_ok:
                return {"ok": True, "info": last_info}
            time.sleep(0.45)
        return {"ok": False, "info": last_info}

    def _bluez_stabilize_target(self, path: str, target_address: str) -> Dict[str, Any]:
        outputs: List[str] = []
        initial_info = self._bluez_fetch_device_info(target_address, path=path)
        if initial_info.get("services_resolved") is True:
            return {
                "ok": True,
                "info": initial_info,
                "raw_output": "",
                "phase": "pre_resolved",
            }
        connect = self._bluez_call_with_progress_wait(path, "Connect", timeout=12.0, settle_seconds=5.0)
        outputs.append((connect.get("stdout") or connect.get("stderr") or "").strip())
        wait_connected = self._bluez_wait_for_device_state(path, target_address, timeout=6.0, require_connected=True)
        info_after_connect = wait_connected.get("info") if isinstance(wait_connected.get("info"), dict) else {}
        if info_after_connect.get("services_resolved") is True:
            return {
                "ok": True,
                "info": info_after_connect,
                "raw_output": "\n".join(item for item in outputs if item),
                "phase": "connected_services",
            }
        pair = None
        if not bool(info_after_connect.get("paired")):
            pair = self._bluez_call_with_progress_wait(path, "Pair", timeout=18.0, settle_seconds=8.0)
            outputs.append((pair.get("stdout") or pair.get("stderr") or "").strip())
        trust = None
        if not bool(info_after_connect.get("trusted")):
            trust = self._bluez_set_trusted(path, True)
            outputs.append((trust.get("stdout") or trust.get("stderr") or "").strip())
        reconnect = self._bluez_call_with_progress_wait(path, "Connect", timeout=12.0, settle_seconds=6.0)
        outputs.append((reconnect.get("stdout") or reconnect.get("stderr") or "").strip())
        wait_services = self._bluez_wait_for_device_state(path, target_address, timeout=10.0, require_connected=False, require_services=True)
        info_after_pair = wait_services.get("info") if isinstance(wait_services.get("info"), dict) else {}
        if not bool(info_after_pair.get("services_resolved")):
            snapshot = self._bluez_gatt_snapshot(target_address, path=path)
            if int(snapshot.get("service_count") or 0) > 0:
                info_after_pair = {**info_after_pair, "services_resolved": True}
        return {
            "ok": bool(info_after_pair),
            "info": info_after_pair,
            "raw_output": "\n".join(item for item in outputs if item),
            "phase": "paired_services" if info_after_pair.get("services_resolved") else "paired_no_services",
            "errors": [item.get("stderr") for item in (connect, pair, trust, reconnect) if item and item.get("stderr")],
        }

    def _bluez_gatt_snapshot(self, address: str = "", path: str = "") -> Dict[str, Any]:
        device_path = str(path or "").strip() or self._bluez_find_device_path(address) or self._bluez_device_path(address)
        services = 0
        characteristics = 0
        descriptors = 0
        readable = 0
        writable = 0
        notify_count = 0
        indicate_count = 0
        cccd_count = 0
        unauth_readable = 0
        unauth_writable = 0
        attribute_lines: List[str] = []
        service_records: List[Dict[str, Any]] = []
        for child in self._bluez_introspect_children(device_path):
            if "/service" not in child:
                continue
            service_props = self._bluez_get_all(child, "org.bluez.GattService1")
            if service_props:
                services += 1
                service_uuid = str(service_props.get("UUID") or "").strip()
                service_entry = {
                    "path": child,
                    "uuid": service_uuid,
                    "primary": bool(service_props.get("Primary")),
                    "characteristics": [],
                }
                if service_uuid and len(attribute_lines) < 18:
                    attribute_lines.append(f"svc {service_uuid}")
            for grandchild in self._bluez_introspect_children(child):
                if "/char" not in grandchild and "/chrc" not in grandchild:
                    continue
                ch_props = self._bluez_get_all(grandchild, "org.bluez.GattCharacteristic1")
                if not ch_props:
                    continue
                characteristics += 1
                flags = [str(item).lower() for item in (ch_props.get("Flags") or [])]
                can_read = any(flag in flags for flag in ("read", "encrypt-read", "encrypt-authenticated-read", "secure-read"))
                can_write = any(flag in flags for flag in ("write", "write-without-response", "encrypt-write", "encrypt-authenticated-write", "secure-write"))
                requires_auth = any(flag in flags for flag in ("encrypt-read", "encrypt-authenticated-read", "secure-read", "encrypt-write", "encrypt-authenticated-write", "secure-write", "authorize", "authenticated-signed-writes"))
                if can_read:
                    readable += 1
                    if not requires_auth:
                        unauth_readable += 1
                if can_write:
                    writable += 1
                    if not requires_auth:
                        unauth_writable += 1
                if any(flag in flags for flag in ("notify", "indicate")):
                    notify_count += 1
                if "indicate" in flags:
                    indicate_count += 1
                ch_uuid = str(ch_props.get("UUID") or "").strip()
                if ch_uuid and len(attribute_lines) < 18:
                    attribute_lines.append(f"char {ch_uuid} {'/'.join(flags[:3])}")
                descriptor_entries: List[Dict[str, Any]] = []
                for descriptor_path in self._bluez_introspect_children(grandchild):
                    if "/desc" not in descriptor_path:
                        continue
                    desc_props = self._bluez_get_all(descriptor_path, "org.bluez.GattDescriptor1")
                    if not desc_props:
                        continue
                    descriptors += 1
                    desc_uuid = str(desc_props.get("UUID") or "").strip().lower()
                    desc_flags = [str(item).lower() for item in (desc_props.get("Flags") or [])]
                    if desc_uuid == "00002902-0000-1000-8000-00805f9b34fb" or desc_uuid == "2902":
                        cccd_count += 1
                    if desc_uuid and len(attribute_lines) < 18:
                        attribute_lines.append(f"desc {desc_uuid} {'/'.join(desc_flags[:2])}")
                    descriptor_entries.append(
                        {
                            "path": descriptor_path,
                            "uuid": desc_uuid,
                            "flags": desc_flags,
                        }
                    )
                service_entry["characteristics"].append(
                    {
                        "path": grandchild,
                        "uuid": ch_uuid,
                        "flags": flags,
                        "readable": can_read,
                        "writable": can_write,
                        "notifiable": any(flag in flags for flag in ("notify", "indicate")),
                        "requires_auth": requires_auth,
                        "descriptors": descriptor_entries,
                    }
                )
            if service_props:
                service_records.append(service_entry)
        return {
            "service_count": services,
            "characteristic_count": characteristics,
            "descriptor_count": descriptors,
            "readable_count": readable,
            "writable_count": writable,
            "notify_count": notify_count,
            "indicate_count": indicate_count,
            "cccd_count": cccd_count,
            "unauth_readable_count": unauth_readable,
            "unauth_writable_count": unauth_writable,
            "attribute_lines": attribute_lines,
            "services": service_records,
        }

    def _bluez_reconnect_probe(self, address: str = "", path: str = "") -> Dict[str, Any]:
        device_path = str(path or "").strip() or self._bluez_find_device_path(address) or self._bluez_device_path(address)
        attempts = 2
        successes = 0
        output_lines: List[str] = []
        for _ in range(attempts):
            connect = self._bluez_dbus_call(device_path, "org.bluez.Device1", "Connect", timeout=10.0)
            output_lines.append((connect.get("stdout") or connect.get("stderr") or "").strip())
            time.sleep(0.4)
            info = self._bluez_fetch_device_info(address, path=device_path)
            if info.get("connected") is True or info.get("paired") is True:
                successes += 1
            disconnect = self._bluez_dbus_call(device_path, "org.bluez.Device1", "Disconnect", timeout=6.0)
            output_lines.append((disconnect.get("stdout") or disconnect.get("stderr") or "").strip())
            time.sleep(0.3)
        if successes >= 2:
            result = "stable_reconnect"
        elif successes == 1:
            result = "partial_reconnect"
        else:
            result = "reconnect_failed"
        return {
            "attempted": True,
            "result": result,
            "detail": f"{successes}/{attempts} reconnect attempts succeeded",
            "connect_attempts": attempts,
            "successful_attempts": successes,
            "raw_output": "\n".join(item for item in output_lines if item)[-2000:],
        }

    def _gatt_characteristics_from_snapshot(self, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        characteristics: List[Dict[str, Any]] = []
        for service in list((snapshot or {}).get("services") or []):
            service_uuid = str(service.get("uuid") or "").lower()
            for characteristic in list(service.get("characteristics") or []):
                flags = [str(item).lower() for item in (characteristic.get("flags") or [])]
                descriptor_uuids = [
                    str(item.get("uuid") or "").lower()
                    for item in (characteristic.get("descriptors") or [])
                    if str(item.get("uuid") or "").strip()
                ]
                characteristics.append(
                    {
                        "service_uuid": service_uuid,
                        "path": str(characteristic.get("path") or ""),
                        "uuid": str(characteristic.get("uuid") or "").lower(),
                        "flags": flags,
                        "requires_auth": bool(characteristic.get("requires_auth")),
                        "descriptors": descriptor_uuids,
                        "notifiable": bool(characteristic.get("notifiable")) or any(flag in flags for flag in ("notify", "indicate")),
                    }
                )
        return characteristics

    def _bluez_notify_surface_probe(self, snapshot: Dict[str, Any], *, max_attempts: int = 3) -> Dict[str, Any]:
        characteristics = self._gatt_characteristics_from_snapshot(snapshot)
        eligible = [
            item for item in characteristics
            if item.get("path")
            and (
                bool(item.get("notifiable"))
                or "00002902-0000-1000-8000-00805f9b34fb" in (item.get("descriptors") or [])
                or "2902" in (item.get("descriptors") or [])
            )
        ]
        if not eligible:
            return {
                "id": "notify_surface",
                "label": "Notify/Indicate Surface Audit",
                "status": "blocked",
                "executed": False,
                "detail": "No notify or indicate characteristic with descriptor evidence was available for subscription audit.",
                "findings": [],
                "evidence": ["no_notify_or_indicate_paths"],
                "metrics": {
                    "eligible_paths": 0,
                    "attempted_paths": 0,
                    "successful_subscriptions": 0,
                    "blocked_subscriptions": 0,
                },
            }

        attempts: List[Dict[str, Any]] = []
        successes = 0
        blocked = 0
        for characteristic in eligible[:max_attempts]:
            start = self._bluez_dbus_call(
                str(characteristic.get("path") or ""),
                "org.bluez.GattCharacteristic1",
                "StartNotify",
                timeout=6.0,
            )
            start_blob = f"{start.get('stdout') or ''}\n{start.get('stderr') or ''}".lower()
            success = bool(start.get("ok")) and not any(
                token in start_blob for token in ("not supported", "not permitted", "failed", "error")
            )
            stop = {"ok": False, "stdout": "", "stderr": ""}
            if success:
                stop = self._bluez_dbus_call(
                    str(characteristic.get("path") or ""),
                    "org.bluez.GattCharacteristic1",
                    "StopNotify",
                    timeout=6.0,
                )
                successes += 1
            else:
                blocked += 1
            attempts.append(
                {
                    "path": str(characteristic.get("path") or ""),
                    "uuid": str(characteristic.get("uuid") or ""),
                    "service_uuid": str(characteristic.get("service_uuid") or ""),
                    "flags": list(characteristic.get("flags") or []),
                    "requires_auth": bool(characteristic.get("requires_auth")),
                    "subscription_result": "subscribed" if success else "blocked",
                    "subscription_detail": (start.get("stderr") or start.get("stdout") or "subscription attempt finished").strip()[:220],
                    "stop_detail": (stop.get("stderr") or stop.get("stdout") or "").strip()[:180],
                }
            )
        status = "completed" if successes > 0 else "blocked"
        detail = f"{successes}/{len(attempts)} subscription probe(s) succeeded"
        if not successes and attempts:
            detail = f"{len(attempts)} subscription probe(s) blocked by target or host policy"
        findings = []
        if successes > 0:
            findings.append("subscription path accepted on at least one notify/indicate characteristic")
        if blocked > 0:
            findings.append("some notify/indicate paths rejected subscription attempts")
        return {
            "id": "notify_surface",
            "label": "Notify/Indicate Surface Audit",
            "status": status,
            "executed": True,
            "detail": detail,
            "findings": findings,
            "attempts": attempts,
            "evidence": [
                f"eligible_paths={len(eligible)}",
                f"attempted_paths={len(attempts)}",
                f"successful_subscriptions={successes}",
                f"blocked_subscriptions={blocked}",
            ],
            "metrics": {
                "eligible_paths": len(eligible),
                "attempted_paths": len(attempts),
                "successful_subscriptions": successes,
                "blocked_subscriptions": blocked,
            },
        }

    def _build_harder_test_results(
        self,
        *,
        pre_gatt: Dict[str, Any],
        post_gatt: Dict[str, Any],
        reconnect_gatt: Dict[str, Any],
        reconnect_probe: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        pre = pre_gatt if isinstance(pre_gatt, dict) else {}
        post = post_gatt if isinstance(post_gatt, dict) else {}
        reconnect = reconnect_gatt if isinstance(reconnect_gatt, dict) else {}
        pre_to_post = self._gatt_delta(pre, post)
        post_to_reconnect = self._gatt_delta(post, reconnect)
        reconnect_result = str((reconnect_probe or {}).get("result") or "not_attempted")
        results: List[Dict[str, Any]] = [
            self._bluez_notify_surface_probe(post),
            {
                "id": "auth_boundary",
                "label": "Authorization Boundary Probe",
                "status": "completed" if int(post.get("service_count") or 0) > 0 else "blocked",
                "executed": int(post.get("service_count") or 0) > 0,
                "detail": (
                    f"post-trust delta: {pre_to_post['writable_count_delta']} writable, "
                    f"{pre_to_post['unauth_writable_count_delta']} unauth-w, "
                    f"{pre_to_post['unauth_readable_count_delta']} unauth-r"
                ) if int(post.get("service_count") or 0) > 0 else "No post-trust GATT surface was available for boundary comparison.",
                "findings": [
                    finding for finding in [
                        "new writable paths appeared after trust" if pre_to_post["writable_count_delta"] > 0 else "",
                        "new unauthenticated writable paths appeared after trust" if pre_to_post["unauth_writable_count_delta"] > 0 else "",
                        "new unauthenticated readable paths appeared after trust" if pre_to_post["unauth_readable_count_delta"] > 0 else "",
                    ] if finding
                ],
                "evidence": [
                    f"service_count_pre={int(pre.get('service_count') or 0)}",
                    f"service_count_post={int(post.get('service_count') or 0)}",
                    f"writable_delta={pre_to_post['writable_count_delta']}",
                    f"unauth_writable_delta={pre_to_post['unauth_writable_count_delta']}",
                    f"unauth_readable_delta={pre_to_post['unauth_readable_count_delta']}",
                ],
                "metrics": pre_to_post,
            },
            {
                "id": "service_changed",
                "label": "Service-Changed / Drift Audit",
                "status": "completed" if int(post.get("service_count") or 0) > 0 else "blocked",
                "executed": int(post.get("service_count") or 0) > 0,
                "detail": (
                    f"reconnect delta: {post_to_reconnect['service_count_delta']} service, "
                    f"{post_to_reconnect['characteristic_count_delta']} char, "
                    f"{post_to_reconnect['descriptor_count_delta']} desc"
                ) if int(post.get("service_count") or 0) > 0 else "No post-trust service map was available for reconnect drift comparison.",
                "findings": [
                    finding for finding in [
                        "service inventory changed after reconnect" if post_to_reconnect["service_count_delta"] != 0 else "",
                        "characteristic inventory changed after reconnect" if post_to_reconnect["characteristic_count_delta"] != 0 else "",
                        "descriptor inventory changed after reconnect" if post_to_reconnect["descriptor_count_delta"] != 0 else "",
                    ] if finding
                ],
                "evidence": [
                    f"service_delta={post_to_reconnect['service_count_delta']}",
                    f"characteristic_delta={post_to_reconnect['characteristic_count_delta']}",
                    f"descriptor_delta={post_to_reconnect['descriptor_count_delta']}",
                ],
                "metrics": post_to_reconnect,
            },
            {
                "id": "reconnect_drift",
                "label": "Reconnect Drift Audit",
                "status": "completed" if reconnect_result != "not_attempted" else "blocked",
                "executed": reconnect_result != "not_attempted",
                "detail": str((reconnect_probe or {}).get("detail") or "Reconnect probe not attempted."),
                "findings": [
                    finding for finding in [
                        "reconnect failed during validation session" if reconnect_result == "reconnect_failed" else "",
                        "reconnect was only partially successful" if reconnect_result == "partial_reconnect" else "",
                        "reconnect was stable across validation probes" if reconnect_result == "stable_reconnect" else "",
                    ] if finding
                ],
                "evidence": [
                    f"reconnect_result={reconnect_result}",
                    f"successful_attempts={int((reconnect_probe or {}).get('successful_attempts') or 0)}",
                    f"connect_attempts={int((reconnect_probe or {}).get('connect_attempts') or 0)}",
                ],
                "metrics": {
                    "connect_attempts": int((reconnect_probe or {}).get("connect_attempts") or 0),
                    "successful_attempts": int((reconnect_probe or {}).get("successful_attempts") or 0),
                },
            },
        ]
        return results

    def _bluez_run_validation_session(self, address: str) -> Dict[str, Any]:
        if not address:
            return {"ok": False, "error": "no_address"}
        if not self._bluez_dbus_available():
            return {"ok": False, "error": "dbus_unavailable"}
        resolved_device = self._aggregate_device_by_address(address)
        resolution = self._resolve_target_materialization(resolved_device, force_retry=True) if resolved_device else {}
        if resolution.get("host_path"):
            bootstrap = {
                "ok": str(resolution.get("state") or "").upper() in {"MATERIALIZED", "VALIDATION_READY", "CANDIDATE"},
                "path": str(resolution.get("host_path") or ""),
                "detail": str(resolution.get("detail") or "device object materialized via targeted resolution"),
                "raw_output": json.dumps(resolution, ensure_ascii=True),
            }
        else:
            bootstrap = self._bluez_discovery_bootstrap(address, timeout=6.0)
        if not bootstrap.get("ok"):
            return {
                "ok": False,
                "error": bootstrap.get("error") or "device_not_materialized",
                "detail": bootstrap.get("detail") or "target did not appear as a BlueZ device object",
                "raw_output": bootstrap.get("raw_output") or "",
                "resolution": resolution,
            }
        path = str(bootstrap.get("path") or self._bluez_device_path(address))
        target_address = str((resolution or {}).get("host_address") or address).strip()
        pre_info = self._bluez_fetch_device_info(target_address, path=path)
        pre_gatt = self._bluez_gatt_snapshot(target_address, path=path)
        session = self._bluez_stabilize_target(path, target_address)
        step_outputs: List[str] = [str(session.get("raw_output") or "").strip()]
        post_info = session.get("info") if isinstance(session.get("info"), dict) else self._bluez_fetch_device_info(target_address, path=path)
        gatt = self._bluez_gatt_snapshot(target_address, path=path)
        reconnect_probe = self._bluez_reconnect_probe(target_address, path=path)
        reconnect_info = self._bluez_fetch_device_info(target_address, path=path)
        reconnect_gatt = self._bluez_gatt_snapshot(target_address, path=path)
        harder_test_results = self._build_harder_test_results(
            pre_gatt=pre_gatt,
            post_gatt=gatt,
            reconnect_gatt=reconnect_gatt,
            reconnect_probe=reconnect_probe,
        )
        disconnect = self._bluez_dbus_call(path, "org.bluez.Device1", "Disconnect", timeout=8.0)
        step_outputs.append((disconnect.get("stdout") or disconnect.get("stderr") or "").strip())
        return {
            "ok": True,
            "path": path,
            "target_address": target_address,
            "resolution": resolution,
            "pre_info": pre_info,
            "pre_gatt": pre_gatt,
            "post_info": post_info,
            "gatt": gatt,
            "reconnect_probe": reconnect_probe,
            "reconnect_info": reconnect_info,
            "reconnect_gatt": reconnect_gatt,
            "harder_test_results": harder_test_results,
            "raw_output": "\n".join(item for item in step_outputs if item),
            "errors": [*list(session.get("errors") or []), *(item.get("stderr") for item in (disconnect,) if item.get("stderr"))],
        }

    def _run_bluetoothctl_session(self, commands: list[str], timeout: float = 18.0) -> Dict[str, Any]:
        output_chunks: list[str] = []
        pid = None
        master_fd = None
        timed_out = False
        try:
            pid, master_fd = os.forkpty()
            if pid == 0:
                if Path("/run/dbus/system_bus_socket").exists():
                    os.environ.setdefault("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket")
                os.execvp("bluetoothctl", ["bluetoothctl"])

            def read_available(wait_window: float) -> None:
                until = time.monotonic() + max(0.0, wait_window)
                while time.monotonic() < until:
                    ready, _, _ = select.select([master_fd], [], [], 0.15)
                    if not ready:
                        continue
                    chunk = os.read(master_fd, 8192)
                    if not chunk:
                        break
                    output_chunks.append(chunk.decode("utf-8", errors="ignore"))

            def prompt_ready() -> bool:
                output = "".join(output_chunks).lower()
                return "[bluetooth]" in output or "agent registered" in output or "waiting to connect to bluetoothd" not in output

            deadline = time.monotonic() + float(timeout)
            read_available(1.8)
            if not prompt_ready() and time.monotonic() < deadline:
                read_available(1.4)
            command_stream = ["power on", "agent NoInputNoOutput", *commands, "quit"]
            for command in command_stream:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                os.write(master_fd, f"{command}\n".encode("utf-8", errors="ignore"))
                command_lower = command.lower()
                wait_window = 0.9
                if any(token in command_lower for token in ("connect ", "pair ", "trust ", "untrust ", "disconnect ", "info ", "menu gatt", "list-attributes")):
                    wait_window = 2.6
                read_available(min(max(0.3, wait_window), max(0.3, deadline - time.monotonic())))
            while time.monotonic() < deadline:
                child_pid, status = os.waitpid(pid, os.WNOHANG)
                if child_pid == pid:
                    returncode = os.waitstatus_to_exitcode(status)
                    output = "".join(output_chunks).strip()
                    return {
                        "ok": returncode == 0 and not timed_out,
                        "returncode": returncode,
                        "stdout": output,
                        "stderr": "",
                        "output": output,
                    }
                ready, _, _ = select.select([master_fd], [], [], 0.2)
                if ready:
                    chunk = os.read(master_fd, 8192)
                    if chunk:
                        output_chunks.append(chunk.decode("utf-8", errors="ignore"))
                    else:
                        break
            timed_out = True
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
            returncode = None
            try:
                _, status = os.waitpid(pid, 0)
                returncode = os.waitstatus_to_exitcode(status)
            except Exception:
                pass
            output = "".join(output_chunks).strip()
            return {
                "ok": False,
                "returncode": returncode,
                "stdout": output,
                "stderr": f"bluetoothctl timed out after {timeout:.1f}s",
                "output": output,
            }
        except Exception as exc:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": str(exc),
                "output": str(exc),
            }
        finally:
            try:
                if master_fd is not None:
                    os.close(master_fd)
            except Exception:
                pass

    def _parse_bluez_bool(self, raw: str) -> bool | None:
        lowered = str(raw or "").strip().lower()
        if lowered in {"yes", "true"}:
            return True
        if lowered in {"no", "false"}:
            return False
        return None

    def _parse_bluetoothctl_info(self, output: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "name": "",
            "alias": "",
            "paired": None,
            "trusted": None,
            "connected": None,
            "blocked": None,
            "legacy_pairing": None,
            "uuids": [],
        }
        uuid_values: list[str] = []
        for raw in output.splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized = key.strip().lower()
            clean_value = value.strip()
            if normalized == "name":
                info["name"] = clean_value
            elif normalized == "alias":
                info["alias"] = clean_value
            elif normalized == "paired":
                info["paired"] = self._parse_bluez_bool(clean_value)
            elif normalized == "trusted":
                info["trusted"] = self._parse_bluez_bool(clean_value)
            elif normalized == "connected":
                info["connected"] = self._parse_bluez_bool(clean_value)
            elif normalized == "blocked":
                info["blocked"] = self._parse_bluez_bool(clean_value)
            elif normalized == "legacypairing":
                info["legacy_pairing"] = self._parse_bluez_bool(clean_value)
            elif normalized == "uuid":
                uuid_values.append(clean_value.split(" ", 1)[0].strip())
        info["uuids"] = sorted(set(uuid_values))
        return info

    def _parse_bluetoothctl_gatt(self, output: str) -> Dict[str, Any]:
        summary = {
            "service_count": 0,
            "characteristic_count": 0,
            "readable_count": 0,
            "writable_count": 0,
            "notify_count": 0,
            "attribute_lines": [],
        }
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            lowered = line.lower()
            if "[primary]" in lowered or ("service" in lowered and "uuid" in lowered):
                summary["service_count"] += 1
            if "[char]" in lowered or "characteristic" in lowered or "char-" in lowered:
                summary["characteristic_count"] += 1
            if "read" in lowered:
                summary["readable_count"] += 1
            if "write" in lowered:
                summary["writable_count"] += 1
            if "notify" in lowered or "indicate" in lowered:
                summary["notify_count"] += 1
            if len(summary["attribute_lines"]) < 18 and ("service" in lowered or "char" in lowered or "desc" in lowered):
                summary["attribute_lines"].append(line)
        return summary

    def _tool_readiness(self) -> Dict[str, Dict[str, Any]]:
        tools = {
            "tshark": ["tshark", "-v"],
            "bettercap": ["bettercap", "--help"],
            "bluetoothctl": ["bluetoothctl", "--help"],
            "hcitool": ["hcitool", "--help"],
            "btmon": ["btmon", "-h"],
            "btattach": ["btattach", "-h"],
        }
        readiness: Dict[str, Dict[str, Any]] = {}
        for name, probe_cmd in tools.items():
            path = shutil.which(name)
            readiness[name] = {
                "installed": bool(path),
                "path": path,
                "detail": "",
            }
            if path:
                result = self._run_capture_command(probe_cmd, timeout=4.0)
                text = (result.get("stdout") or result.get("stderr") or "").strip().splitlines()
                readiness[name]["detail"] = text[0] if text else ""
        scapy_nrf_path = Path("/usr/lib/python3/dist-packages/scapy/contrib/nrf_sniffer.py")
        readiness["scapy_nrf_sniffer"] = {
            "installed": scapy_nrf_path.exists(),
            "path": str(scapy_nrf_path),
            "detail": "Scapy Nordic Sniffer parser present" if scapy_nrf_path.exists() else "Scapy Nordic Sniffer parser not found",
        }
        bluez_runtime = self._bluez_runtime_status()
        readiness["bluez_dbus"] = {
            "installed": bool(bluez_runtime.get("dbus_send_path")) and bool(bluez_runtime.get("busctl_path")),
            "path": ", ".join(item for item in [bluez_runtime.get("dbus_send_path"), bluez_runtime.get("busctl_path")] if item),
            "detail": str(bluez_runtime.get("detail") or ""),
            "service_registered": bool(bluez_runtime.get("service_registered")),
            "system_bus_ready": bool(bluez_runtime.get("system_bus_ready")),
        }
        host_readiness = self._bluez_host_readiness()
        readiness["bluez_host"] = {
            "installed": True,
            "path": ", ".join(str(item.get("name") or "") for item in (host_readiness.get("adapters") or [])),
            "detail": str(host_readiness.get("detail") or ""),
            "ready": bool(host_readiness.get("ready")),
            "state": str(host_readiness.get("state") or "unknown"),
            "adapter_count": int(host_readiness.get("adapter_count") or 0),
            "powered_adapter_count": int(host_readiness.get("powered_adapter_count") or 0),
        }
        return readiness

    def _read_serial_probe(self, path: str, baudrate: int, seconds: float = 1.2) -> bytes:
        if serial is None:
            return b""
        handle = None
        try:
            handle = serial.Serial(path, baudrate=9600, rtscts=True, timeout=0.1, write_timeout=0.1)
            handle.baudrate = baudrate
            if hasattr(handle, "reset_input_buffer"):
                handle.reset_input_buffer()
            started = time.monotonic()
            chunks: list[bytes] = []
            while time.monotonic() - started < seconds:
                pending = getattr(handle, "in_waiting", 0) or 1
                chunk = handle.read(pending)
                if chunk:
                    chunks.append(chunk)
                    if sum(len(item) for item in chunks) >= 96:
                        break
            return b"".join(chunks)
        except Exception:
            return b""
        finally:
            try:
                if handle is not None:
                    handle.close()
            except Exception:
                pass

    def _classify_serial_probe(self, sample: bytes, baudrate: int) -> Dict[str, Any]:
        if not sample:
            return {
                "protocol": "no_data",
                "detail": "no serial frames observed",
                "baudrate": baudrate,
                "collector_ready": False,
                "sample_hex": "",
                "firmware_mode": "unknown",
            }

        sample_hex = sample[:48].hex()
        if b"\xAB" in sample and b"\xBC" in sample:
            return {
                "protocol": "nordic_sniffer",
                "detail": f"Nordic BLE sniffer framing detected at {baudrate} baud",
                "baudrate": baudrate,
                "collector_ready": True,
                "sample_hex": sample_hex,
                "firmware_mode": "sniffer",
            }

        if sample.startswith(b"\xC0") and sample.count(b"\xC0") >= 2:
            frame = next((part for part in sample.split(b"\xC0") if part), b"")
            heartbeat = frame.hex() if frame else sample_hex
            detail = (
                f"Connectivity-style serial framing detected at {baudrate} baud "
                f"(heartbeat {heartbeat[:24]})"
            )
            if frame.startswith(bytes.fromhex("002f00d1017e")):
                detail = (
                    f"nRF52 Connectivity firmware detected at {baudrate} baud "
                    f"(heartbeat {heartbeat[:24]})"
                )
            return {
                "protocol": "nrf52_connectivity",
                "detail": detail,
                "baudrate": baudrate,
                "collector_ready": False,
                "sample_hex": sample_hex,
                "firmware_mode": "connectivity",
            }

        return {
            "protocol": "unknown_serial",
            "detail": f"serial traffic observed at {baudrate} baud but not recognized as Nordic sniffer framing",
            "baudrate": baudrate,
            "collector_ready": False,
            "sample_hex": sample_hex,
            "firmware_mode": "unknown",
        }

    def _probe_serial_transport(self, path: str) -> Dict[str, Any]:
        cached = self._serial_probe_cache.get(path)
        now = time.time()
        if cached and now - float(cached.get("timestamp") or 0) < 20:
            return cached

        probe: Dict[str, Any] = {
            "timestamp": now,
            "path": path,
            "protocol": "unavailable",
            "detail": "serial probing unavailable",
            "baudrate": None,
            "collector_ready": False,
            "sample_hex": "",
            "firmware_mode": "unknown",
        }
        if serial is None:
            probe["detail"] = "pyserial is not installed"
            self._serial_probe_cache[path] = probe
            return probe

        for baudrate in self.NORDIC_SNIFFER_RATES:
            sample = self._read_serial_probe(path, baudrate)
            classification = self._classify_serial_probe(sample, baudrate)
            classification["timestamp"] = now
            classification["path"] = path
            if classification.get("protocol") != "no_data":
                probe = classification
                break
            probe = classification

        self._serial_probe_cache[path] = probe
        return probe

    def _reset_scan_state(self) -> None:
        self.scan_stages = [
            {"id": "sensor", "label": "Sensor / Firmware Check", "state": "idle", "detail": "", "percent": 0},
            {"id": "tooling", "label": "Tool Readiness", "state": "idle", "detail": "", "percent": 0},
            {"id": "collect", "label": "nRF Collection Attempt", "state": "idle", "detail": "", "percent": 0},
            {"id": "parse", "label": "Event Parse", "state": "idle", "detail": "", "percent": 0},
            {"id": "active", "label": "Active Product Test", "state": "idle", "detail": "", "percent": 0},
            {"id": "enrich", "label": "Intel Enrichment", "state": "idle", "detail": "", "percent": 0},
            {"id": "retain", "label": "Retention", "state": "idle", "detail": "", "percent": 0},
        ]
        self.last_tool_errors = []
        self.active_tools = []

    def _set_stage(self, stage_id: str, state: str, detail: str, percent: int) -> None:
        for stage in self.scan_stages:
            if stage["id"] == stage_id:
                stage["state"] = state
                stage["detail"] = detail
                stage["percent"] = max(0, min(100, int(percent)))
                break

    def _parse_hcitool_output(self, output: str) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        now = time.time()
        for raw in output.splitlines():
            line = raw.strip()
            if not line or line.startswith("LE Scan"):
                continue
            parts = re.split(r"\s{2,}|\t+", line)
            if len(parts) < 2:
                continue
            address = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else "Unknown BLE Device"
            if re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", address):
                devices.append(
                    {
                        "timestamp": now,
                        "sensor_id": "host-hci0",
                        "channel": 37,
                        "address": address,
                        "address_type": "public",
                        "name": name or "Unknown BLE Device",
                        "service_uuids": [],
                        "packet_type": "advertisement",
                        "connectable": True,
                        "scannable": True,
                        "priority_class": "general",
                        "verdict": "Observed via hcitool",
                    }
                )
        return devices

    def _persist_active_validation(self, device_key: str, active_validation: Dict[str, Any], notes: str = "") -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {}
        tasks = self._task_state_map()
        existing = tasks.get(normalized_key) or self._workflow_descriptor("validate")
        now = time.time()
        task = {
            "device_key": normalized_key,
            "workflow": "validate",
            "state": "active_tested",
            "label": "Validate",
            "summary": "Active product test completed against owned target.",
            "notes": str(notes or existing.get("notes") or "").strip(),
            "source": existing.get("source") or "auto_scan",
            "updated_at": now,
            "validation": existing.get("validation") if isinstance(existing.get("validation"), dict) else {},
            "active_validation": active_validation,
            "pairing_transcript": active_validation.get("pairing_transcript") if isinstance(active_validation.get("pairing_transcript"), dict) else {},
            "validation_confidence": active_validation.get("validation_confidence") if isinstance(active_validation.get("validation_confidence"), dict) else {},
            "validation_suite": existing.get("validation_suite") if isinstance(existing.get("validation_suite"), dict) else {},
            "validation_run": existing.get("validation_run") if isinstance(existing.get("validation_run"), dict) else {},
            "gatt_test": existing.get("gatt_test") if isinstance(existing.get("gatt_test"), dict) else {},
            "validation_history": list(existing.get("validation_history") or []),
        }
        tasks[normalized_key] = task
        self._save_task_state_map(tasks)
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": now,
                "event_type": "active_validation",
                "device_key": normalized_key,
                "connect_result": active_validation.get("connect_result"),
                "service_count": active_validation.get("service_count"),
                "characteristic_count": active_validation.get("characteristic_count"),
                "writable_count": active_validation.get("writable_count"),
            },
        )
        return task

    def _active_validation_outcome(
        self,
        *,
        resolution_state: str,
        connect_result: str,
        info: Dict[str, Any],
        gatt: Dict[str, Any],
        reconnect_probe: Dict[str, Any],
    ) -> Dict[str, Any]:
        resolution_ready = resolution_state in {"MATERIALIZED", "VALIDATION_READY"}
        services_resolved = bool(info.get("services_resolved"))
        service_count = int(gatt.get("service_count") or 0)
        char_count = int(gatt.get("characteristic_count") or 0)
        reconnect_result = str(reconnect_probe.get("result") or "").lower()

        if service_count > 0 or char_count > 0:
            trust_state = "trusted" if bool(info.get("trusted")) else ("paired" if bool(info.get("paired")) else "partial")
            if connect_result in {"connected", "paired"} and (services_resolved or service_count > 0):
                return {
                    "outcome": "verified",
                    "trust_state": trust_state,
                    "gatt_state": "mapped",
                    "operator_summary": "BlueZ returned a usable GATT surface and trust-state evidence for this target.",
                    "next_best_action": "Review unauthenticated reads/writes and validate reconnect behavior against this surface.",
                }
            return {
                "outcome": "partial",
                "trust_state": trust_state,
                "gatt_state": "mapped",
                "operator_summary": "BlueZ exposed a GATT surface, but pairing or service-resolution did not fully complete.",
                "next_best_action": "Repeat the active test and compare the discovered GATT surface against a fully paired run.",
            }

        if connect_result in {"blocked_unresolved", "device_unresolved"} or not resolution_ready:
            return {
                "outcome": "blocked",
                "trust_state": "unresolved",
                "gatt_state": "unavailable",
                "operator_summary": "Host target not materialized in BlueZ; trust and GATT validation blocked.",
                "next_best_action": "Repeat targeted host discovery until this asset materializes as a Device1 object.",
            }
        if connect_result in {"connected", "paired"} and (services_resolved or service_count > 0 or char_count > 0):
            trust_state = "trusted" if bool(info.get("trusted")) else ("paired" if bool(info.get("paired")) else "connected")
            return {
                "outcome": "verified",
                "trust_state": trust_state,
                "gatt_state": "mapped",
                "operator_summary": "BlueZ resolved the target and returned trust and GATT evidence.",
                "next_best_action": "Review writable and unauthenticated GATT surfaces, then run reconnect misuse cases.",
            }
        if connect_result in {"connected", "paired", "materialized_only"}:
            reconnect_note = "Reconnect stable." if reconnect_result == "stable_reconnect" else "Reconnect evidence incomplete."
            return {
                "outcome": "partial",
                "trust_state": "partial",
                "gatt_state": "partial" if service_count or char_count else "pending",
                "operator_summary": f"Target materialized, but trust/GATT evidence is incomplete. {reconnect_note}",
                "next_best_action": "Repeat the active test until ServicesResolved is true and a GATT map is present.",
            }
        if connect_result == "failed":
            return {
                "outcome": "failed",
                "trust_state": "failed",
                "gatt_state": "unavailable",
                "operator_summary": "BlueZ resolved the target, but the connect/pair flow failed.",
                "next_best_action": "Review adapter state, pairing prompts, and target availability before retrying.",
            }
        return {
            "outcome": "partial",
            "trust_state": "unknown",
            "gatt_state": "unknown",
            "operator_summary": "Validation produced only partial state evidence.",
            "next_best_action": "Repeat active validation and capture a btmon trace for this target.",
        }

    def _gatt_delta(self, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, int]:
        return {
            "service_count_delta": int(after.get("service_count") or 0) - int(before.get("service_count") or 0),
            "characteristic_count_delta": int(after.get("characteristic_count") or 0) - int(before.get("characteristic_count") or 0),
            "descriptor_count_delta": int(after.get("descriptor_count") or 0) - int(before.get("descriptor_count") or 0),
            "readable_count_delta": int(after.get("readable_count") or 0) - int(before.get("readable_count") or 0),
            "writable_count_delta": int(after.get("writable_count") or 0) - int(before.get("writable_count") or 0),
            "notify_count_delta": int(after.get("notify_count") or 0) - int(before.get("notify_count") or 0),
            "indicate_count_delta": int(after.get("indicate_count") or 0) - int(before.get("indicate_count") or 0),
            "cccd_count_delta": int(after.get("cccd_count") or 0) - int(before.get("cccd_count") or 0),
            "unauth_readable_count_delta": int(after.get("unauth_readable_count") or 0) - int(before.get("unauth_readable_count") or 0),
            "unauth_writable_count_delta": int(after.get("unauth_writable_count") or 0) - int(before.get("unauth_writable_count") or 0),
        }

    def _build_gatt_differential(
        self,
        pre_gatt: Dict[str, Any],
        post_gatt: Dict[str, Any],
        reconnect_gatt: Dict[str, Any],
    ) -> Dict[str, Any]:
        pre = pre_gatt if isinstance(pre_gatt, dict) else {}
        post = post_gatt if isinstance(post_gatt, dict) else {}
        reconnect = reconnect_gatt if isinstance(reconnect_gatt, dict) else {}
        pre_to_post = self._gatt_delta(pre, post)
        post_to_reconnect = self._gatt_delta(post, reconnect)
        highlights: List[str] = []
        if pre_to_post["service_count_delta"] > 0:
            highlights.append(f"{pre_to_post['service_count_delta']} service(s) appeared after trust")
        if pre_to_post["characteristic_count_delta"] > 0:
            highlights.append(f"{pre_to_post['characteristic_count_delta']} characteristic(s) appeared after trust")
        if pre_to_post["writable_count_delta"] > 0:
            highlights.append(f"{pre_to_post['writable_count_delta']} writable path(s) appeared after trust")
        if pre_to_post["descriptor_count_delta"] > 0:
            highlights.append(f"{pre_to_post['descriptor_count_delta']} descriptor(s) appeared after trust")
        if pre_to_post["unauth_writable_count_delta"] > 0:
            highlights.append(f"{pre_to_post['unauth_writable_count_delta']} unauth writable path(s) appeared after trust")
        if pre_to_post["notify_count_delta"] > 0:
            highlights.append(f"{pre_to_post['notify_count_delta']} notify/indicate path(s) appeared after trust")
        if post_to_reconnect["service_count_delta"] != 0 or post_to_reconnect["characteristic_count_delta"] != 0:
            highlights.append("reconnect changed the exposed GATT surface")
        if not highlights:
            highlights.append("no strong GATT differential captured")
        return {
            "snapshots": {
                "pre_pair": pre,
                "post_pair": post,
                "reconnect": reconnect,
            },
            "pre_to_post": pre_to_post,
            "post_to_reconnect": post_to_reconnect,
            "summary": " · ".join(highlights[:3]),
            "highlights": highlights[:6],
        }

    def _run_active_validation(self, device: Dict[str, Any], session_owner: str = "") -> Dict[str, Any]:
        address = str(device.get("address") or "").strip()
        device_key = str(device.get("device_key") or "").strip().lower()
        tested_at = time.time()
        gate = self._auditability_gate(device)
        if not address:
            return {
                "device_key": device_key,
                "tested_at": tested_at,
                "attempted": False,
                "connect_result": "skipped_no_address",
                "detail": "no bluetooth address available",
                "info": {},
                "service_count": 0,
                "characteristic_count": 0,
                "readable_count": 0,
                "writable_count": 0,
                "notify_count": 0,
                "unauth_readable_count": 0,
                "unauth_writable_count": 0,
                "attribute_lines": [],
                "services": [],
                "errors": ["no_address"],
                "reconnect_probe": {
                    "attempted": False,
                    "result": "skipped_no_address",
                    "detail": "device has no bluetooth address",
                    "connect_attempts": 0,
                    "successful_attempts": 0,
                },
            }
        if gate["state"] != "AUDITABLE":
            return self._blocked_validation_result(
                device,
                tested_at=tested_at,
                connect_result="blocked_auditability_gate",
                detail=gate["reason"],
                next_best_action=gate["action"],
                error_code="auditability_gate_blocked",
            )
        if not bool(device.get("connectable")):
            return {
                "device_key": device_key,
                "tested_at": tested_at,
                "attempted": False,
                "connect_result": "skipped_nonconnectable",
                "detail": "device only advertised as non-connectable during the scan window",
                "info": {},
                "service_count": 0,
                "characteristic_count": 0,
                "readable_count": 0,
                "writable_count": 0,
                "notify_count": 0,
                "unauth_readable_count": 0,
                "unauth_writable_count": 0,
                "attribute_lines": [],
                "services": [],
                "errors": [],
                "reconnect_probe": {
                    "attempted": False,
                    "result": "skipped_nonconnectable",
                    "detail": "device only advertised as non-connectable during passive collection",
                    "connect_attempts": 0,
                    "successful_attempts": 0,
                },
            }

        bluez_runtime = self._bluez_runtime_status()
        if not bool(bluez_runtime.get("available")):
            detail = str(bluez_runtime.get("detail") or "BlueZ DBus runtime is unavailable on this host.")
            blocked = self._blocked_validation_result(
                device,
                tested_at=tested_at,
                connect_result="blocked_bluez_unavailable",
                detail="BlueZ is not available on the host, so active BLE trust and GATT validation cannot start.",
                next_best_action="Start or install the BlueZ service on this host, then retry the active BLE workflow.",
                error_code="bluez_unavailable",
            )
            blocked["errors"] = ["bluez_unavailable", detail]
            blocked["host_prerequisites"] = {"bluez_dbus": bluez_runtime}
            blocked["detail"] = detail
            return blocked

        owner_id = str(session_owner or f"active_validation:{threading.get_ident()}:{tested_at:.6f}")
        session_claim = self._claim_target_session(device_key, owner_id, "bluez_validation", wait_timeout=25.0)
        if not session_claim.get("ok"):
            return {
                "device_key": device_key,
                "tested_at": tested_at,
                "attempted": True,
                "outcome": "blocked",
                "connect_result": "device_busy",
                "detail": str(session_claim.get("detail") or "another validation is already running on this target"),
                "operator_summary": "Another BLE validation workflow is already operating on this target.",
                "next_best_action": "Wait for the current target operation to finish, then retry the selected test.",
                "trust_state": "busy",
                "gatt_state": "busy",
                "info": {},
                "services_resolved": False,
                "service_count": 0,
                "characteristic_count": 0,
                "readable_count": 0,
                "writable_count": 0,
                "notify_count": 0,
                "unauth_readable_count": 0,
                "unauth_writable_count": 0,
                "attribute_lines": [],
                "services": [],
                "errors": [str(session_claim.get("error") or "device_busy"), str(session_claim.get("detail") or "")],
                "raw_output": "",
                "pairing_transcript": {
                    "challenge_type": "unknown",
                    "prompt_seen": False,
                    "paired_after": False,
                    "trusted_after": False,
                    "services_resolved": False,
                    "summary": "target session busy",
                },
                "validation_confidence": {"score": 0, "level": "low", "summary": "low confidence · target busy"},
                "reconnect_probe": {
                    "attempted": False,
                    "result": "device_busy",
                    "detail": str(session_claim.get("detail") or "another validation is already running on this target"),
                    "connect_attempts": 0,
                    "successful_attempts": 0,
                },
                "resolution": self._resolve_target_materialization(device),
            }
        try:
            dbus_session = self._bluez_run_validation_session(address)
            resolution = dbus_session.get("resolution") if isinstance(dbus_session.get("resolution"), dict) else self._resolve_target_materialization(device)
            if dbus_session.get("ok"):
                info = dbus_session.get("post_info") if isinstance(dbus_session.get("post_info"), dict) else {}
                gatt = dbus_session.get("gatt") if isinstance(dbus_session.get("gatt"), dict) else {}
                pre_gatt = dbus_session.get("pre_gatt") if isinstance(dbus_session.get("pre_gatt"), dict) else {}
                reconnect_gatt = dbus_session.get("reconnect_gatt") if isinstance(dbus_session.get("reconnect_gatt"), dict) else {}
                reconnect_info = dbus_session.get("reconnect_info") if isinstance(dbus_session.get("reconnect_info"), dict) else {}
                reconnect_probe = dbus_session.get("reconnect_probe") if isinstance(dbus_session.get("reconnect_probe"), dict) else {}
                output = str(dbus_session.get("raw_output") or "")
                errors = [str(item).strip() for item in (dbus_session.get("errors") or []) if str(item).strip()]
            else:
                info = self._bluez_fetch_device_info(address)
                gatt = {
                    "service_count": 0,
                    "characteristic_count": 0,
                    "readable_count": 0,
                    "writable_count": 0,
                    "notify_count": 0,
                    "unauth_readable_count": 0,
                    "unauth_writable_count": 0,
                    "attribute_lines": [],
                    "services": [],
                }
                pre_gatt = {}
                reconnect_gatt = {}
                reconnect_info = {}
                reconnect_probe = {
                    "attempted": False,
                    "result": str(dbus_session.get("error") or "validation_unavailable"),
                    "detail": str(dbus_session.get("detail") or "BlueZ device validation path unavailable"),
                    "connect_attempts": 0,
                    "successful_attempts": 0,
                    "raw_output": str(dbus_session.get("raw_output") or ""),
                }
                output = str(dbus_session.get("raw_output") or "")
                errors = []
                if dbus_session.get("error"):
                    errors.append(str(dbus_session.get("error")))
                if dbus_session.get("detail"):
                    errors.append(str(dbus_session.get("detail")))
        finally:
            self._release_target_session(device_key, owner_id)
        lowered = output.lower()
        resolution_state = str((resolution or {}).get("state") or "").upper()
        if "connection successful" in lowered or info.get("connected") is True:
            connect_result = "connected"
        elif "failed to connect" in lowered or "not available" in lowered or "le-connection-abort-by-local" in lowered:
            connect_result = "failed"
        elif info.get("paired") is True:
            connect_result = "paired"
        elif str(dbus_session.get("error") or "") == "device_not_materialized":
            connect_result = "blocked_unresolved"
        elif resolution_state in {"CANDIDATE", "MATERIALIZED", "VALIDATION_READY"}:
            connect_result = "materialized_only"
        else:
            connect_result = "unknown"

        pairing_transcript = {
            "challenge_type": (
                "pin" if "enter pin" in lowered or "pin code" in lowered else
                "numeric comparison" if "confirm passkey" in lowered or "request confirmation" in lowered else
                "passkey" if "passkey" in lowered else
                "legacy pin" if info.get("legacy_pairing") is True else
                "unknown"
            ),
            "prompt_seen": any(token in lowered for token in ("enter pin", "pin code", "passkey", "confirm passkey", "request confirmation")),
            "paired_after": bool(info.get("paired")),
            "trusted_after": bool(info.get("trusted")),
            "services_resolved": bool(info.get("services_resolved")),
            "method_confidence": "high" if any(token in lowered for token in ("enter pin", "pin code", "passkey", "confirm passkey", "request confirmation")) else ("moderate" if info.get("legacy_pairing") is True else "unknown"),
            "lifecycle_events": [
                {"stage": "pre_pair", "paired": bool((dbus_session.get("pre_info") or {}).get("paired")), "trusted": bool((dbus_session.get("pre_info") or {}).get("trusted")), "services_resolved": bool((dbus_session.get("pre_info") or {}).get("services_resolved"))},
                {"stage": "post_pair", "paired": bool(info.get("paired")), "trusted": bool(info.get("trusted")), "services_resolved": bool(info.get("services_resolved"))},
                {"stage": "reconnect", "paired": bool(reconnect_info.get("paired")), "trusted": bool(reconnect_info.get("trusted")), "services_resolved": bool(reconnect_info.get("services_resolved"))},
            ],
            "summary": (
                f"{'paired' if info.get('paired') else 'not paired'} · "
                f"{'trusted' if info.get('trusted') else 'not trusted'} · "
                f"{'services resolved' if int(gatt.get('service_count') or 0) > 0 else 'no services'}"
            ),
        }
        gatt_differential = self._build_gatt_differential(pre_gatt, gatt, reconnect_gatt)
        harder_test_results = list(dbus_session.get("harder_test_results") or [])
        validation_confidence_score = 0
        if connect_result in {"connected", "paired"}:
            validation_confidence_score += 35
        if bool(info.get("paired")):
            validation_confidence_score += 20
        if bool(info.get("trusted")):
            validation_confidence_score += 10
        if int(gatt.get("service_count") or 0) > 0:
            validation_confidence_score += 20
        if int(gatt.get("characteristic_count") or 0) > 0:
            validation_confidence_score += 10
        if pairing_transcript["prompt_seen"]:
            validation_confidence_score += 5
        validation_confidence_level = "low"
        if validation_confidence_score >= 70:
            validation_confidence_level = "high"
        elif validation_confidence_score >= 40:
            validation_confidence_level = "medium"
        outcome = self._active_validation_outcome(
            resolution_state=resolution_state,
            connect_result=connect_result,
            info=info,
            gatt=gatt,
            reconnect_probe=reconnect_probe,
        )
        detail = (
            f"{outcome['outcome']} · {connect_result} · {resolution_state.lower() or 'observed'} · "
            f"{gatt.get('service_count') or 0} svc · {gatt.get('characteristic_count') or 0} char · "
            f"{gatt.get('writable_count') or 0} writable"
        )
        return {
            "device_key": device_key,
            "tested_at": tested_at,
            "attempted": True,
            "outcome": outcome["outcome"],
            "connect_result": connect_result,
            "detail": detail,
            "operator_summary": outcome["operator_summary"],
            "next_best_action": outcome["next_best_action"],
            "trust_state": outcome["trust_state"],
            "gatt_state": outcome["gatt_state"],
            "info": info,
            "services_resolved": bool(info.get("services_resolved")),
            "service_count": int(gatt.get("service_count") or 0),
            "characteristic_count": int(gatt.get("characteristic_count") or 0),
            "readable_count": int(gatt.get("readable_count") or 0),
            "writable_count": int(gatt.get("writable_count") or 0),
            "notify_count": int(gatt.get("notify_count") or 0),
            "unauth_readable_count": int(gatt.get("unauth_readable_count") or 0),
            "unauth_writable_count": int(gatt.get("unauth_writable_count") or 0),
            "attribute_lines": list(gatt.get("attribute_lines") or []),
            "services": list(gatt.get("services") or []),
            "errors": errors,
            "raw_output": output[-4000:],
            "pairing_transcript": pairing_transcript,
            "pairing_method": pairing_transcript.get("challenge_type") or "unknown",
            "validation_confidence": {
                "score": validation_confidence_score,
                "level": validation_confidence_level,
                "summary": f"{validation_confidence_level} confidence · score {validation_confidence_score}",
            },
            "reconnect_probe": reconnect_probe,
            "reconnect_info": reconnect_info,
            "gatt_snapshots": {
                "pre_pair": pre_gatt,
                "post_pair": gatt,
                "reconnect": reconnect_gatt,
            },
            "gatt_differential": gatt_differential,
            "harder_test_results": harder_test_results,
            "resolution": resolution,
            "blocked_state": dict((resolution or {}).get("blocked_state") or {}),
            "failure_reason": self._validation_failure_reason(device, {
                "attempted": True,
                "connect_result": connect_result,
                "resolution": resolution,
                "pairing_transcript": pairing_transcript,
                "service_count": int(gatt.get("service_count") or 0),
                "characteristic_count": int(gatt.get("characteristic_count") or 0),
            }).get("reason"),
            "action_guidance": self._validation_failure_reason(device, {
                "attempted": True,
                "connect_result": connect_result,
                "resolution": resolution,
                "pairing_transcript": pairing_transcript,
                "service_count": int(gatt.get("service_count") or 0),
                "characteristic_count": int(gatt.get("characteristic_count") or 0),
            }).get("action"),
        }

    def _run_reconnect_probe(self, address: str) -> Dict[str, Any]:
        if not address:
            return {
                "attempted": False,
                "result": "skipped_no_address",
                "detail": "device has no bluetooth address",
                "connect_attempts": 0,
                "successful_attempts": 0,
            }
        reconnect_cmd = self._run_bluetoothctl_session(
            [
                f"connect {address}",
                f"disconnect {address}",
                f"connect {address}",
                f"info {address}",
                f"disconnect {address}",
            ],
            timeout=10.0,
        )
        output = str(reconnect_cmd.get("output") or "")
        success_hits = output.lower().count("connection successful")
        info = self._parse_bluetoothctl_info(output)
        if success_hits >= 2:
            result = "stable_reconnect"
        elif success_hits == 1 or info.get("connected") is True:
            result = "partial_reconnect"
        elif "failed to connect" in output.lower():
            result = "reconnect_failed"
        else:
            result = "reconnect_unknown"
        return {
            "attempted": True,
            "result": result,
            "detail": f"{success_hits}/2 reconnect attempts succeeded",
            "connect_attempts": 2,
            "successful_attempts": success_hits,
            "raw_output": output[-2000:],
        }

    def run_active_validation(self, device_key: str) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"status": "error", "error": "device_key is required"}
        claim = self._claim_device_operation(normalized_key, "active_test")
        if not claim.get("ok"):
            return {"status": "error", "error": claim.get("error"), "detail": claim.get("detail")}
        device = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None)
        try:
            if device is None:
                return {"status": "error", "error": "device not found"}
            result = self._run_active_validation(device)
            task = self._persist_active_validation(normalized_key, result)
            return {"status": "completed", "active_validation": result, "task": task}
        finally:
            self._release_device_operation(normalized_key, "active_test")

    def _run_active_validation_cycle(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for device in devices:
            result = self._run_active_validation(device)
            self._persist_active_validation(str(device.get("device_key") or ""), result)
            results.append(result)
        return results

    def _scenario_status(self, *, passed: bool | None = None, weak: bool = False) -> str:
        if passed is True:
            return "pass"
        if passed is False:
            return "fail"
        if weak:
            return "weak"
        return "unknown"

    def _build_validation_suite(self, device: Dict[str, Any], scenario_ids: list[str] | None = None) -> Dict[str, Any]:
        selected_ids = [item for item in (scenario_ids or self._default_validation_scenario_ids()) if item in self.VALIDATION_SCENARIOS]
        validation = device.get("validation") if isinstance(device.get("validation"), dict) else {}
        active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        reconnect_probe = active_validation.get("reconnect_probe") if isinstance(active_validation.get("reconnect_probe"), dict) else {}
        scenarios: list[dict[str, Any]] = []
        for scenario_id in selected_ids:
            meta = self.VALIDATION_SCENARIOS.get(scenario_id, {})
            if scenario_id == "pairing_posture":
                pairable = str(device.get("pairable") or "no").lower()
                pairable_confidence = str(device.get("pairable_confidence") or "low")
                manual = str(validation.get("manual_result") or "").lower()
                resolution_state = str(device.get("resolution_state") or "observed").lower()
                status = self._scenario_status(
                    passed=True if manual == "paired" or (pairable == "yes" and pairable_confidence == "high" and resolution_state in {"materialized", "validation_ready"}) else None,
                    weak=pairable == "yes",
                )
                detail = (
                    f"{pairable} · {device.get('pairable_reason') or 'unknown'} · "
                    f"{resolution_state} · "
                    f"{', '.join(device.get('pairing_methods') or []) if device.get('pairing_methods') else 'pairing method not observed'}"
                )
            elif scenario_id == "bond_lifecycle":
                bond_events = int(device.get("bond_events") or 0)
                repair_flags = int(device.get("repair_flags") or 0)
                silent_patterns = int(device.get("silent_pairing_patterns") or 0)
                pairing_failures = int(device.get("pairing_failures") or 0)
                status = self._scenario_status(
                    passed=True if bond_events == 0 and repair_flags == 0 and silent_patterns == 0 and pairing_failures == 0 else False
                )
                detail = f"{bond_events} bond events · {repair_flags} re-pair flags · {pairing_failures} failures · {silent_patterns} silent patterns"
            elif scenario_id == "reconnect_resilience":
                result = str(reconnect_probe.get("result") or "").lower()
                status = self._scenario_status(
                    passed=True if result == "stable_reconnect" else (False if result == "reconnect_failed" else None),
                    weak=result in {"partial_reconnect", "reconnect_unknown"} or not reconnect_probe.get("attempted"),
                )
                detail = reconnect_probe.get("detail") or "reconnect probe not attempted"
            elif scenario_id == "gatt_surface":
                services = int(active_validation.get("service_count") or 0)
                characteristics = int(active_validation.get("characteristic_count") or 0)
                writable = int(active_validation.get("writable_count") or 0)
                unauth = int(active_validation.get("unauth_writable_count") or device.get("writable_unauth_count") or 0)
                unauth_readable = int(active_validation.get("unauth_readable_count") or 0)
                status = self._scenario_status(
                    passed=True if services > 0 or characteristics > 0 else None,
                    weak=writable > 0 or unauth > 0 or (services == 0 and characteristics == 0),
                )
                detail = f"{services} svc · {characteristics} char · {writable} writable · {unauth} unauth-w · {unauth_readable} unauth-r"
            else:
                anomalies = len(device.get("anomaly_flags") or [])
                vuln_count = len(device.get("vulnerability_matches") or [])
                status = self._scenario_status(passed=True if anomalies == 0 and vuln_count == 0 else None, weak=anomalies > 0 or vuln_count > 0)
                detail = f"{anomalies} anomalies · {vuln_count} matched risk families"
            scenarios.append(
                {
                    "id": scenario_id,
                    "label": meta.get("label") or scenario_id,
                    "layer": meta.get("layer") or "validation",
                    "summary": meta.get("summary") or "",
                    "status": status,
                    "detail": detail,
                }
            )

        statuses = Counter(item.get("status") for item in scenarios)
        suite_status = "pass"
        if statuses.get("fail"):
            suite_status = "fail"
        elif statuses.get("weak"):
            suite_status = "weak"
        elif statuses.get("unknown") and not statuses.get("pass"):
            suite_status = "unknown"
        return {
            "status": suite_status,
            "scenario_count": len(scenarios),
            "scenarios": scenarios,
            "updated_at": time.time(),
        }

    def _suite_from_validation_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        results = list(run.get("validation_results") or [])
        label_map = {
            "adversary_emulation": "Adversary Flow",
            "trust_lifecycle": "Trust State",
            "legacy_pin_audit": "PIN Audit",
            "security_boundary": "Auth Boundary",
            "misuse_case": "Misuse Flow",
            "stress_testing": "Stress Loop",
            "identity_emulation": "Identity Path",
            "post_association_surface": "GATT Surface",
            "behavioral_anomaly": "Anomaly Scan",
            "path_recommendation": "Next Path",
            "evidence_replay": "Replay Record",
        }
        scenarios: list[dict[str, Any]] = []
        for item in results:
            status = str(item.get("status") or "").strip().lower()
            if not status:
                deviation = str(item.get("deviation") or "").strip().lower()
                status = "pass"
                if "anomal" in deviation or "unauthorized" in deviation or "failed" in deviation or "instability" in deviation:
                    status = "weak"
                if "requires review" in deviation or "replacement" in deviation:
                    status = "weak"
            scenarios.append(
                {
                    "id": str(item.get("module_id") or "validation"),
                    "label": label_map.get(str(item.get("module_id") or "validation"), str(item.get("module_id") or "validation").replace("_", " ").title()),
                    "layer": "validation",
                    "summary": str(item.get("objective") or ""),
                    "status": status,
                    "detail": str(item.get("observed_behavior") or item.get("deviation") or "")[:220],
                }
            )
        overall = "verified"
        if any(item.get("status") == "fail" for item in scenarios):
            overall = "failed"
        elif any(item.get("status") == "weak" for item in scenarios):
            overall = "partial"
        elif not scenarios or any(item.get("status") == "unknown" for item in scenarios):
            overall = "blocked"
        return {
            "status": overall if scenarios else "unknown",
            "scenario_count": len(scenarios),
            "scenarios": scenarios,
            "updated_at": float(run.get("timestamp") or time.time()),
        }

    def _derive_validation_from_suite(self, device: Dict[str, Any], active_validation: Dict[str, Any], validation_run: Dict[str, Any], notes: str = "") -> Dict[str, Any]:
        connect_result = str(active_validation.get("connect_result") or "").strip().lower()
        info = active_validation.get("info") if isinstance(active_validation.get("info"), dict) else {}
        trust_lifecycle = validation_run.get("trust_lifecycle") if isinstance(validation_run.get("trust_lifecycle"), dict) else {}
        pin_audit = validation_run.get("pin_audit") if isinstance(validation_run.get("pin_audit"), dict) else {}
        pairing_transcript = validation_run.get("pairing_transcript") if isinstance(validation_run.get("pairing_transcript"), dict) else {}
        validation_confidence = validation_run.get("validation_confidence") if isinstance(validation_run.get("validation_confidence"), dict) else {}
        capture_plan = validation_run.get("capture_plan") if isinstance(validation_run.get("capture_plan"), dict) else {}
        pairing_method = str(trust_lifecycle.get("pairing_method") or "").strip().lower()

        if connect_result in {"connected", "paired"}:
            pairable_verdict = "yes"
            manual_result = "paired"
        elif connect_result in {"failed", "skipped_nonconnectable", "skipped_no_address"}:
            pairable_verdict = "no"
            manual_result = "rejected"
        else:
            pairable_verdict = "yes" if bool(device.get("connectable")) else "no"
            manual_result = "unknown"

        legacy_pairing_flag = info.get("legacy_pairing")
        pin_risk = str(pin_audit.get("risk") or "").strip().lower()
        if pin_risk in {"likely", "unlikely"}:
            legacy_pin_risk = pin_risk
        elif legacy_pairing_flag is True or pairing_method in {"passkey", "legacy pin", "pin"}:
            legacy_pin_risk = "likely"
        elif legacy_pairing_flag is False or pairing_method in {"numeric comparison", "oob"}:
            legacy_pin_risk = "unlikely"
        else:
            legacy_pin_risk = "unknown"

        return {
            "pairable_verdict": pairable_verdict,
            "legacy_pin_risk": legacy_pin_risk,
            "manual_result": manual_result,
            "notes": str(notes or "").strip(),
            "updated_at": time.time(),
            "source": "validation_suite",
            "pin_audit": pin_audit,
            "pairing_transcript": pairing_transcript,
            "validation_confidence": validation_confidence,
            "capture_plan": capture_plan,
        }

    def run_validation_suite(
        self,
        device_key: str,
        scenario_ids: list[str] | None = None,
        owned_target: bool = False,
        notes: str = "",
    ) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"status": "error", "error": "device_key is required"}
        if not self.lab_mode:
            return {"status": "error", "error": "lab mode is required"}
        if not owned_target:
            return {"status": "error", "error": "owned_target confirmation is required"}
        claim = self._claim_device_operation(normalized_key, "validation_suite")
        if not claim.get("ok"):
            return {"status": "error", "error": claim.get("error"), "detail": claim.get("detail")}
        device = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None)
        try:
            if device is None:
                return {"status": "error", "error": "device not found"}
            gate = self._auditability_gate(device)
            if gate["state"] != "AUDITABLE":
                blocked_active = self._blocked_validation_result(
                    device,
                    tested_at=time.time(),
                    connect_result="blocked_auditability_gate",
                    detail=gate["reason"],
                    next_best_action=gate["action"],
                    error_code="auditability_gate_blocked",
                )
                self._persist_active_validation(normalized_key, blocked_active, notes=notes)
                return {
                    "status": "blocked",
                    "error": "auditability_gate_blocked",
                    "detail": gate["reason"],
                    "active_validation": blocked_active,
                }
            validation_run = self.validation_engine.execute_workflow(device, owned_target=owned_target, notes=notes)
            if validation_run.get("status") == "error":
                return validation_run
            session_owner = f"validation_suite:{threading.get_ident()}:{time.time():.6f}"
            active_validation = self._run_active_validation(device, session_owner=session_owner)
            self._persist_active_validation(normalized_key, active_validation, notes=notes)
            refreshed = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None) or device
            suite = self._suite_from_validation_run(validation_run)
            if str(active_validation.get("outcome") or "") == "blocked":
                suite["status"] = "blocked"
            elif str(active_validation.get("outcome") or "") == "failed":
                suite["status"] = "failed"
            elif str(active_validation.get("outcome") or "") == "partial" and suite.get("status") == "verified":
                suite["status"] = "partial"
            tasks = self._task_state_map()
            existing = tasks.get(normalized_key) or self._workflow_descriptor("validate")
            derived_validation = self._derive_validation_from_suite(refreshed, active_validation, validation_run, notes=notes)
            history = list(existing.get("validation_history") or [])
            history.insert(
                0,
                {
                    "run_id": validation_run.get("run_id"),
                    "timestamp": validation_run.get("timestamp"),
                    "status": suite.get("status"),
                    "scenario_count": suite.get("scenario_count"),
                },
            )
            history = history[:10]
            tasks[normalized_key] = {
                "device_key": normalized_key,
                "workflow": "validate",
                "state": "validated" if suite.get("status") in {"verified", "partial", "failed", "blocked"} else "validation_ready",
                "label": existing.get("label") or "Validate",
                "summary": "Owned-target validation suite executed.",
                "notes": str(notes or existing.get("notes") or "").strip(),
                "source": existing.get("source") or "manual",
                "updated_at": time.time(),
                "validation": derived_validation,
                "active_validation": active_validation,
                "validation_suite": suite,
                "validation_run": validation_run,
                "pairing_transcript": validation_run.get("pairing_transcript") if isinstance(validation_run.get("pairing_transcript"), dict) else {},
                "validation_confidence": validation_run.get("validation_confidence") if isinstance(validation_run.get("validation_confidence"), dict) else {},
                "capture_plan": validation_run.get("capture_plan") if isinstance(validation_run.get("capture_plan"), dict) else {},
                "gatt_test": existing.get("gatt_test") if isinstance(existing.get("gatt_test"), dict) else {},
                "validation_history": history,
            }
            self._save_task_state_map(tasks)
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": time.time(),
                    "event_type": "validation_suite",
                    "device_key": normalized_key,
                    "suite_status": suite.get("status"),
                    "scenario_count": suite.get("scenario_count"),
                    "run_id": validation_run.get("run_id"),
                },
            )
            return {
                "status": "completed",
                "validation_suite": suite,
                "validation_run": validation_run,
                "active_validation": active_validation,
                "task": tasks[normalized_key],
            }
        finally:
            self._release_device_operation(normalized_key, "validation_suite")

    def run_scan(
        self,
        duration_seconds: int | float = DEFAULT_SCAN_SECONDS,
        stop_event: threading.Event | None = None,
        observation_sink: Callable[[Dict[str, Any]], Any] | None = None,
    ) -> Dict[str, Any]:
        if not self._scan_lock.acquire(blocking=False):
            return {
                "status": "busy",
                "error": "BLE NR5 scan already running.",
                "scan": self.last_scan,
                "stages": self.scan_stages,
            }
        try:
            scan_seconds = max(4, min(300, int(duration_seconds or self.DEFAULT_SCAN_SECONDS)))
            self._reset_scan_state()
            sensors = self._discover_sensors()
            collector_ready_sensors = [sensor for sensor in sensors if sensor.get("collector_ready")]
            sensor_detail = "no BLE NR5 sensor detected"
            sensor_state = "error"
            sensor_percent = 10
            if sensors:
                first_probe = (sensors[0].get("transport_probe") or {}).get("detail") or "transport not probed"
                sensor_detail = f"{len(sensors)} sensor(s) detected. {first_probe}"
                sensor_state = "completed" if collector_ready_sensors else "active"
                sensor_percent = 100 if collector_ready_sensors else 55
            self._set_stage("sensor", sensor_state, sensor_detail, sensor_percent)

            readiness = self._tool_readiness()
            installed_tools = [name for name, item in readiness.items() if item.get("installed")]
            self.active_tools = installed_tools
            tooling_detail = ", ".join(installed_tools) if installed_tools else "no decode / analysis tools detected"
            self._set_stage("tooling", "completed" if installed_tools else "error", tooling_detail, 100 if installed_tools else 10)

            collector_attempts: List[Dict[str, Any]] = []
            observations: List[Dict[str, Any]] = []
            if sensors:
                collector_attempts.append(
                    self._run_nordic_serial_scan(
                        sensors[0],
                        scan_seconds,
                        stop_event=stop_event,
                        observation_sink=observation_sink,
                    )
                )
            else:
                collector_attempts.append(
                    {
                        "tool": "nrf52840",
                        "ok": False,
                        "detail": "no nRF52840 sensor is available for BLE NR5 collection",
                        "observation_count": 0,
                        "raw_frame_count": 0,
                    }
                )

            for attempt in collector_attempts:
                observations.extend(attempt.get("observations") or [])
                if not attempt.get("ok") and attempt.get("detail"):
                    self.last_tool_errors.append(f"{attempt.get('tool')}: {attempt.get('detail')}")

            interrupted = bool(stop_event and stop_event.is_set())
            collect_state = "completed" if observations else ("active" if any(item.get("ok") for item in collector_attempts) else "error")
            collect_detail = "; ".join(f"{item['tool']}: {item['detail']}" for item in collector_attempts) or "no collector attempts made"
            if interrupted:
                collect_detail = f"{collect_detail} · stop requested"
            self._set_stage("collect", collect_state, collect_detail, 100 if observations else (70 if any(item.get("ok") for item in collector_attempts) else 45))

            if observation_sink is None:
                for observation in observations:
                    self.record_observation(observation)

            self._set_stage("parse", "completed" if observations else "idle", f"{len(observations)} observations normalized", 100 if observations else 10)
            active_results: List[Dict[str, Any]] = []
            promoted_count = 0
            resolution_attempts = 0
            materialized_count = 0
            current_devices: List[Dict[str, Any]] = []
            if observations:
                current_devices = self._aggregate_devices()
                promoted_count = self._promote_scan_assets(current_devices)
                for device in current_devices:
                    if str((device.get("auditability") or {}).get("state") or "") != "AUDITABLE":
                        continue
                    resolution = self._resolve_target_materialization(device, force_retry=True)
                    resolution_attempts += 1
                    if str(resolution.get("state") or "").upper() in {"MATERIALIZED", "VALIDATION_READY"}:
                        materialized_count += 1
            if observations:
                available_targets = sum(1 for item in self._aggregate_devices() if str((item.get("auditability") or {}).get("state") or "") == "AUDITABLE")
                self._set_stage(
                    "active",
                    "completed" if available_targets else "idle",
                    f"{available_targets} validation-ready target(s) available for manual Active Test / Validation Suite / GATT Test",
                    100 if available_targets else 10,
                )
            else:
                self._set_stage("active", "idle", "manual lab testing becomes available after a successful scan", 10)
            enrich_detail = f"{len(observations)} observations sent to scoring pipeline"
            if resolution_attempts:
                enrich_detail += f" · {materialized_count}/{resolution_attempts} host targets materialized"
            identity_graph = self._build_identity_graph(current_devices if observations else [])
            identity_summary = identity_graph.get("summary") if isinstance(identity_graph, dict) else {}
            if observations:
                enrich_detail += (
                    f" · {int(identity_summary.get('node_count') or 0)} identity nodes"
                    f" · {int(identity_summary.get('correlated_nodes') or 0)} correlated"
                )
            self._set_stage("enrich", "completed" if observations else "idle", enrich_detail, 100 if observations else 10)
            self._set_stage("retain", "completed" if observations else "idle", f"{len(observations)} retained events", 100 if observations else 10)

            self.last_scan = {
                "timestamp": time.time(),
                "duration_seconds": scan_seconds,
                "interrupted": interrupted,
                "collector_attempts": collector_attempts,
                "observation_count": len(observations),
                "promoted_count": promoted_count,
                "active_tested_count": len(active_results),
                "active_connected_count": sum(1 for item in active_results if str(item.get("connect_result") or "") in {"connected", "paired"}),
                "resolution_attempt_count": resolution_attempts,
                "materialized_target_count": materialized_count,
                "tool_readiness": readiness,
                "errors": list(self.last_tool_errors),
                "sensors": sensors,
            }
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": self.last_scan["timestamp"],
                    "event_type": "scan_run",
                    "duration_seconds": scan_seconds,
                    "interrupted": interrupted,
                    "observation_count": len(observations),
                    "promoted_count": promoted_count,
                    "active_tested_count": len(active_results),
                    "resolution_attempt_count": resolution_attempts,
                    "materialized_target_count": materialized_count,
                    "tools": [item["tool"] for item in collector_attempts],
                    "detail": collect_detail,
                },
            )
            if observations:
                self.last_error = ""
            elif self.last_tool_errors:
                self.last_error = self.last_tool_errors[-1]
            return {
                "status": "completed" if observations else ("stopped" if interrupted else "no_results"),
                "scan": self.last_scan,
                "stages": self.scan_stages,
            }
        finally:
            self._scan_lock.release()

    def _discover_tty_candidates(self) -> list[str]:
        candidates: list[str] = []
        serial_dir = Path("/dev/serial/by-id")
        if serial_dir.exists():
            for entry in sorted(serial_dir.iterdir()):
                name = entry.name.lower()
                if "nordic" in name or "nrf" in name or "52840" in name:
                    candidates.append(str(entry))
        for entry in sorted(Path("/dev").glob("ttyACM*")):
            candidates.append(str(entry))
        return candidates

    def _discover_sensors(self) -> list[dict[str, Any]]:
        lsusb_output = self._run_command(["lsusb"])
        tty_candidates = self._discover_tty_candidates()
        sensors: list[dict[str, Any]] = []
        seen_keys: set[str] = set()

        for line in lsusb_output.splitlines():
            lowered = line.lower()
            if "nordic" not in lowered and "nrf52840" not in lowered and "nrf" not in lowered:
                continue
            tty_matches = [
                path for path in tty_candidates
                if "nordic" in path.lower() or "nrf" in path.lower() or "52840" in path.lower()
            ]
            key = line.strip()
            if key in seen_keys:
                continue
            seen_keys.add(key)
            sensors.append(
                {
                    "sensor_id": f"nr5-{len(sensors) + 1}",
                    "label": "Nordic nRF52840 Dongle",
                    "usb_descriptor": line.strip(),
                    "serial_paths": tty_matches or tty_candidates[:2],
                    "ready": True,
                }
            )

        if not sensors:
            for index, path in enumerate(tty_candidates, start=1):
                sensors.append(
                    {
                        "sensor_id": f"nr5-{index}",
                        "label": "nRF52-compatible serial path",
                        "usb_descriptor": "Serial path detected without confirmed lsusb Nordic descriptor.",
                        "serial_paths": [path],
                        "ready": True,
                    }
                )

        for sensor in sensors:
            serial_paths = sensor.get("serial_paths") or []
            preferred_path = str(serial_paths[0]) if serial_paths else ""
            probe = self._probe_serial_transport(preferred_path) if preferred_path else {
                "protocol": "no_serial",
                "detail": "no serial path discovered",
                "collector_ready": False,
                "firmware_mode": "unknown",
                "baudrate": None,
                "sample_hex": "",
                "path": "",
            }
            sensor["scan_path"] = preferred_path
            sensor["collector_ready"] = bool(probe.get("collector_ready"))
            sensor["firmware_mode"] = probe.get("firmware_mode") or "unknown"
            sensor["transport_probe"] = probe
            sensor["ready"] = bool(probe.get("collector_ready"))
        return sensors

    def _nordic_sniffer_encode(self, payload: list[int]) -> bytes:
        output = [0xAB]
        for value in payload:
            if value == 0xAB:
                output.extend([0xCD, 0xAC])
            elif value == 0xBC:
                output.extend([0xCD, 0xBD])
            elif value == 0xCD:
                output.extend([0xCD, 0xCE])
            else:
                output.append(value)
        output.append(0xBC)
        return bytes(output)

    def _nordic_sniffer_send_scan(self, handle: Any, counter: int = 0) -> None:
        packet = [6, 1, 1, counter & 0xFF, (counter >> 8) & 0xFF, 0x07, 0x00]
        handle.write(self._nordic_sniffer_encode(packet))

    def _decode_nordic_frame(self, frame: bytes) -> bytes:
        output = bytearray()
        escape = False
        for value in frame:
            if escape:
                output.append({0xAC: 0xAB, 0xBD: 0xBC, 0xCE: 0xCD}.get(value, value))
                escape = False
                continue
            if value == 0xCD:
                escape = True
                continue
            output.append(value)
        return bytes(output)

    def _split_nordic_frames(self, stream: bytes) -> list[bytes]:
        frames: list[bytes] = []
        active = False
        current = bytearray()
        for value in stream:
            if not active:
                if value == 0xAB:
                    active = True
                    current = bytearray()
                continue
            if value == 0xBC:
                if current:
                    frames.append(self._decode_nordic_frame(bytes(current)))
                active = False
                current = bytearray()
                continue
            current.append(value)
        return frames

    def _extract_nordic_frames_from_buffer(self, buffer: bytearray) -> list[bytes]:
        frames: list[bytes] = []
        cursor = 0
        while True:
            try:
                start = buffer.index(0xAB, cursor)
            except ValueError:
                if cursor:
                    del buffer[:cursor]
                elif len(buffer) > 65536:
                    buffer.clear()
                return frames
            try:
                end = buffer.index(0xBC, start + 1)
            except ValueError:
                if start > 0:
                    del buffer[:start]
                return frames
            payload = bytes(buffer[start + 1 : end])
            if payload:
                frames.append(self._decode_nordic_frame(payload))
            cursor = end + 1

    def _decode_ad_structures(self, payload: bytes) -> dict[str, Any]:
        service_uuids: list[str] = []
        name = ""
        manufacturer_hex = ""
        manufacturer = ""
        appearance = ""
        company_id = None
        service_data_16: list[dict[str, str]] = []
        tx_power = None
        flags = None
        offset = 0
        valid_structures = 0
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            end = offset + 1 + length
            if end > len(payload):
                break
            ad_type = payload[offset + 1]
            value = payload[offset + 2:end]
            valid_structures += 1
            if ad_type == 0x01 and value:
                flags = value[0]
            if ad_type in (0x08, 0x09):
                try:
                    decoded = value.decode("utf-8", errors="ignore").strip()
                    if decoded:
                        name = decoded
                except Exception:
                    pass
            elif ad_type in (0x02, 0x03):
                for idx in range(0, len(value) - 1, 2):
                    service_uuids.append(f"{int.from_bytes(value[idx:idx + 2], 'little'):04x}")
            elif ad_type in (0x06, 0x07):
                for idx in range(0, len(value) - 15, 16):
                    raw_uuid = value[idx:idx + 16]
                    service_uuids.append(raw_uuid[::-1].hex())
            elif ad_type == 0x16 and len(value) >= 2:
                uuid16 = f"{int.from_bytes(value[:2], 'little'):04x}"
                service_uuids.append(uuid16)
                service_data_16.append({"uuid": uuid16, "data_hex": value[2:].hex()})
            elif ad_type == 0x0A and value:
                try:
                    tx_power = int.from_bytes(value[:1], "little", signed=True)
                except Exception:
                    tx_power = None
            elif ad_type == 0x19 and len(value) >= 2:
                appearance = f"{int.from_bytes(value[:2], 'little')}"
            elif ad_type == 0xFF and len(value) >= 2:
                manufacturer_hex = value.hex()
                company_id = int.from_bytes(value[:2], "little")
                manufacturer = self.COMPANY_IDS.get(company_id, f"company_{company_id:04x}")
            offset = end
        result: dict[str, Any] = {
            "name": name,
            "service_uuids": sorted(set(service_uuids)),
            "manufacturer_data_hex": manufacturer_hex,
            "manufacturer": manufacturer,
            "company_id": company_id,
            "service_data_16": service_data_16,
            "flags": flags,
            "valid_structures": valid_structures,
        }
        if tx_power is not None:
            result["tx_power"] = tx_power
        if appearance:
            result["appearance"] = appearance
        return result

    def _score_ad_payload(self, payload: bytes) -> int:
        if not payload:
            return 0
        offset = 0
        score = 0
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                return score + 1
            end = offset + 1 + length
            if end > len(payload):
                return -1
            score += 2
            ad_type = payload[offset + 1]
            value_len = max(0, length - 1)
            if ad_type in {0x08, 0x09, 0x16, 0xFF, 0x02, 0x03, 0x06, 0x07, 0x19, 0x01} and value_len > 0:
                score += 2
            offset = end
        return score

    def _choose_adv_layout(self, body: bytes) -> tuple[bytes, bytes] | None:
        candidates: list[tuple[int, bytes, bytes]] = []
        for offset in (0, 1):
            if len(body) < offset + 6:
                continue
            address_bytes = body[offset:offset + 6]
            ad_payload = body[offset + 6 :]
            score = self._score_ad_payload(ad_payload)
            if score >= 0:
                candidates.append((score, address_bytes, ad_payload))
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0], reverse=True)
        best_score, address_bytes, ad_payload = candidates[0]
        if best_score <= 0 and ad_payload:
            return None
        return address_bytes, ad_payload

    def _format_mac(self, address_bytes: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in address_bytes[::-1])

    def _infer_vendor(self, ad_data: Dict[str, Any], name: str) -> str:
        manufacturer = str(ad_data.get("manufacturer") or "")
        if manufacturer and not manufacturer.startswith("company_"):
            return manufacturer
        service_uuids = {str(item).lower() for item in (ad_data.get("service_uuids") or [])}
        for uuid in service_uuids:
            vendor = self.SERVICE_VENDOR_HINTS.get(uuid)
            if vendor:
                return vendor
        lowered = name.lower()
        for keyword, vendor in {
            "apple": "Apple",
            "airpods": "Apple",
            "samsung": "Samsung",
            "galaxy": "Samsung",
            "sony": "Sony",
            "bose": "Bose",
            "soundlink": "Bose",
            "fitbit": "Fitbit",
            "garmin": "Garmin",
            "google": "Google",
            "pixel": "Google",
            "tile": "Tile",
            "flipper": "Flipper Devices",
        }.items():
            if keyword in lowered:
                return vendor
        return "Unknown"

    def _sanitize_name(self, name: str) -> str:
        cleaned = "".join(char for char in str(name or "") if 32 <= ord(char) <= 126).strip()
        return cleaned or "Unknown BLE Device"

    def _vendor_confidence(self, ad_data: Dict[str, Any], name: str, vendor: str) -> str:
        if vendor == "Unknown":
            return "low"
        manufacturer = str(ad_data.get("manufacturer") or "")
        if manufacturer and not manufacturer.startswith("company_"):
            return "high"
        service_uuids = {str(item).lower() for item in (ad_data.get("service_uuids") or [])}
        if any(uuid in self.SERVICE_VENDOR_HINTS for uuid in service_uuids):
            return "medium"
        if name != "Unknown BLE Device":
            return "medium"
        return "low"

    def _vendor_source(self, ad_data: Dict[str, Any], name: str, vendor: str) -> str:
        manufacturer = str(ad_data.get("manufacturer") or "")
        if manufacturer and not manufacturer.startswith("company_"):
            return "company_id"
        service_uuids = {str(item).lower() for item in (ad_data.get("service_uuids") or [])}
        if any(uuid in self.SERVICE_VENDOR_HINTS for uuid in service_uuids):
            return "service_uuid"
        lowered = str(name or "").lower()
        if lowered and lowered != "unknown ble device" and vendor != "Unknown":
            for keyword in ("apple", "airpods", "samsung", "galaxy", "sony", "bose", "soundlink", "fitbit", "garmin", "google", "pixel", "tile", "flipper"):
                if keyword in lowered:
                    return "name_keyword"
        return "unknown"

    def _classify_asset(self, name: str, service_uuids: list[str], appearance: str) -> tuple[str, str]:
        lowered = name.lower()
        for keyword, device_type, category in self.DEVICE_TYPE_HINTS:
            if keyword in lowered:
                return device_type, category
        service_set = {str(item).lower() for item in service_uuids}
        if "1812" in service_set:
            return "input device", "hid"
        if {"180d", "1808", "1810", "1814", "1816", "1818", "1819", "181d", "181e", "181f", "1820"}.intersection(service_set):
            return "wearable sensor", "wearable"
        if {"fe2c", "fd6f"}.intersection(service_set):
            return "tracker", "tracker"
        if {"1843", "1844", "1845", "184e"}.intersection(service_set):
            return "audio device", "audio"
        if {"181a"}.intersection(service_set):
            return "environment sensor", "industrial_gateway"
        if appearance and appearance in {"961", "962", "963", "964"}:
            return "watch", "wearable"
        return "bluetooth device", "general"

    def _category_confidence(self, name: str, service_uuids: list[str], category: str) -> str:
        if category == "general":
            return "low"
        if name != "Unknown BLE Device":
            return "high"
        if service_uuids:
            return "medium"
        return "low"

    def _address_confidence(self, address_type: str, identity_reason: str) -> str:
        if address_type == "public":
            return "high"
        if identity_reason in {"exact_address_merge", "stable_name"}:
            return "medium"
        return "low"

    def _identity_reason(self, address_type: str, name: str, vendor: str, service_uuids: list[str], manufacturer_hex: str) -> str:
        if address_type == "public":
            return "public_address"
        if name != "Unknown BLE Device":
            return "stable_name"
        if manufacturer_hex:
            return "manufacturer_fingerprint"
        if service_uuids:
            return "service_fingerprint"
        return "rotating_address_only"

    def _build_asset_key(self, address: str, address_type: str, name: str, vendor: str, device_type: str, service_uuids: list[str], manufacturer_hex: str) -> str:
        clean_name = name.strip().lower()
        service_sig = ",".join(sorted(set(service_uuids)))
        if address_type == "public":
            return address.lower()
        if clean_name and clean_name != "unknown ble device":
            return f"name:{vendor.lower()}:{clean_name}"
        if manufacturer_hex:
            prefix = manufacturer_hex[:10]
            return f"fingerprint:{vendor.lower()}:{device_type.lower()}:{service_sig}:{prefix}"
        if service_sig:
            return f"fingerprint:{vendor.lower()}:{device_type.lower()}:{service_sig}"
        return address.lower()

    def _cluster_merge_key(self, device: Dict[str, Any]) -> str:
        cached_resolution = self._cached_resolution(str(device.get("device_key") or ""))
        resolution_confidence = float(cached_resolution.get("resolution_confidence") or 0.0)
        resolution_host_path = str(cached_resolution.get("host_path") or "").strip()
        resolution_host_address = str(cached_resolution.get("host_address") or "").strip().lower()
        if resolution_host_path and resolution_confidence >= 0.30:
            return f"hostpath:{resolution_host_path}"
        if resolution_host_address and resolution_confidence >= 0.55:
            return f"hostaddr:{resolution_host_address}"
        address = str(device.get("address") or "").lower()
        if address and address.count(":") == 5:
            return f"addrcluster:{address}"
        address_parts = address.split(":")
        prefix5 = ":".join(address_parts[:5]) if len(address_parts) == 6 else address
        name = str(device.get("name") or "Unknown BLE Device").strip().lower()
        vendor = str(device.get("vendor") or "unknown").strip().lower()
        device_type = str(device.get("device_type") or "bluetooth device").strip().lower()
        manufacturer_prefix = str(device.get("manufacturer_data_prefix") or "").strip().lower()
        service_sig = ",".join(sorted(str(item).lower() for item in (device.get("service_uuids") or [])))
        if name and name != "unknown ble device":
            return f"namecluster:{vendor}:{name}:{prefix5}"
        if manufacturer_prefix:
            return f"manucluster:{vendor}:{device_type}:{manufacturer_prefix}:{prefix5}"
        if service_sig and str(device.get("address_type") or "") == "random":
            return f"svccluster:{vendor}:{device_type}:{service_sig}:{prefix5}"
        return ""

    def _reconcile_merged_identity(self, device: Dict[str, Any]) -> Dict[str, Any]:
        company_id = device.get("manufacturer_company_id")
        manufacturer = ""
        if company_id is not None:
            manufacturer = self.COMPANY_IDS.get(int(company_id), f"company_{int(company_id):04x}")
        ad_data = {
            "manufacturer": manufacturer,
            "service_uuids": device.get("service_uuids") or [],
        }
        name = self._sanitize_name(device.get("name") or "Unknown BLE Device")
        vendor = self._infer_vendor(ad_data, name)
        if vendor != "Unknown" or str(device.get("vendor") or "Unknown") in {"", "Unknown"}:
            device["vendor"] = vendor
        device["vendor_confidence"] = self._vendor_confidence(ad_data, name, str(device.get("vendor") or "Unknown"))
        device["vendor_source"] = self._vendor_source(ad_data, name, str(device.get("vendor") or "Unknown"))
        device_type, category = self._classify_asset(name, device.get("service_uuids") or [], str(device.get("appearance_class") or ""))
        device["device_type"] = device_type
        if category != "general" or str(device.get("priority_class") or "general") == "general":
            device["priority_class"] = category
        device["category_confidence"] = self._category_confidence(name, device.get("service_uuids") or [], str(device.get("priority_class") or "general"))
        if int(device.get("observation_count") or 0) > 1 and name != "Unknown BLE Device":
            device["identity_confidence"] = "high" if str(device.get("address_type") or "") == "public" else "medium"
            if str(device.get("identity_reason") or "") in {"rotating_address_only", "manufacturer_fingerprint", "service_fingerprint"}:
                device["identity_reason"] = "exact_address_merge"
        device["address_confidence"] = self._address_confidence(str(device.get("address_type") or ""), str(device.get("identity_reason") or ""))
        return device

    def _classification_confidence_level(self, score: int) -> str:
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    def _signal_stability(self, device: Dict[str, Any]) -> tuple[bool, float | None]:
        values = []
        for item in (device.get("rssi_values") or []):
            try:
                values.append(float(item))
            except Exception:
                continue
        if len(values) < 2:
            return False, None
        spread = max(values) - min(values)
        return spread <= 9.0, round(spread, 1)

    def _classification_icon(self, device: Dict[str, Any], classified_type: str) -> str:
        device_type = str(device.get("device_type") or "").strip().lower()
        priority = str(device.get("priority_class") or "").strip().lower()
        if any(keyword in device_type for keyword in ("watch", "band", "wearable")) or priority == "wearable":
            return "⌚"
        if any(keyword in device_type for keyword in ("bulb", "lamp", "light")):
            return "💡"
        if any(keyword in device_type for keyword in ("plug", "outlet")):
            return "🔌"
        if "tv" in device_type:
            return "📺"
        if classified_type == "Mobile":
            return "📱"
        if classified_type == "Beacon":
            return "📡"
        if classified_type == "IoT":
            return "💡"
        return "❓"

    def _classify_protocol(self, device: Dict[str, Any], classified_type: str, vendor: str) -> str:
        service_uuids = list(device.get("service_uuids") or [])
        gatt_readable = int(device.get("gatt_readable_count") or 0)
        gatt_writable = int(device.get("gatt_writable_count") or 0)
        active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        services_resolved = bool(active_validation.get("services_resolved"))
        has_ble_surface = bool(service_uuids) or gatt_readable > 0 or gatt_writable > 0 or services_resolved
        if classified_type == "IoT" and vendor in self.ZIGBEE_INFERENCE_VENDORS and not has_ble_surface:
            return "Zigbee (inferred)"
        if has_ble_surface or bool(device.get("connectable")):
            return "BLE"
        if classified_type == "IoT" and vendor in self.CLOUD_ECOSYSTEM_VENDORS:
            return "BLE + Cloud"
        if classified_type == "Beacon":
            return "Broadcast"
        return "Unknown"

    def _classify_device_intelligence(self, device: Dict[str, Any]) -> Dict[str, Any]:
        fingerprint_match = self.ble_intelligence_engine.classify_device(
            {
                "name": device.get("name"),
                "vendor": device.get("vendor"),
                "company_id": device.get("manufacturer_company_id"),
                "manufacturer_data_prefix": device.get("manufacturer_data_prefix"),
                "service_uuids": device.get("service_uuids") or [],
                "connectable": device.get("connectable"),
                "address_type": device.get("address_type"),
                "advertising_interval_ms": device.get("advertising_interval_ms"),
                "avg_rssi": device.get("avg_rssi"),
                "observation_count": device.get("observation_count"),
                "cluster_size": device.get("preclass_cluster_size"),
            }
        )
        vendor = str(device.get("vendor") or "Unknown").strip() or "Unknown"
        address_type = str(device.get("address_type") or "unknown").strip().lower()
        public_mac = address_type == "public"
        connectable = bool(device.get("connectable"))
        service_uuids = list(device.get("service_uuids") or [])
        stable_signal, signal_spread = self._signal_stability(device)
        observation_count = int(device.get("observation_count") or 0)
        priority = str(device.get("priority_class") or "").strip().lower()
        device_type = str(device.get("device_type") or "").strip().lower()
        known_vendor = vendor not in {"", "Unknown"}
        looks_mobile = (
            vendor in self.PERSONAL_VENDORS
            or priority in {"wearable", "audio", "tracker", "hid"}
            or any(keyword in device_type for keyword in ("watch", "earbuds", "headset", "headphones", "tracker", "keyboard", "mouse", "phone"))
        )
        looks_iot = (
            vendor in self.IOT_VENDORS
            or priority in {"industrial_gateway", "smart_lock"}
            or any(keyword in device_type for keyword in ("sensor", "gateway", "lock", "bulb", "plug", "thermostat", "camera", "hub"))
        )
        minimal_payload = not service_uuids and int(device.get("avg_structure_count") or 0) <= 2
        if not connectable and minimal_payload:
            classified_type = "Beacon"
        elif looks_mobile and (address_type == "random" or connectable):
            classified_type = "Mobile"
        elif looks_iot or (public_mac and stable_signal and observation_count > 1 and (not connectable or priority in {"general", "industrial_gateway", "smart_lock"})):
            classified_type = "IoT"
        else:
            classified_type = "Unknown"

        protocol = self._classify_protocol(device, classified_type, vendor)
        confidence_score = 0
        if known_vendor:
            confidence_score += 30
        if public_mac:
            confidence_score += 20
        if stable_signal:
            confidence_score += 20
        if service_uuids:
            confidence_score += 20
        if observation_count > 1:
            confidence_score += 10
        confidence_level = self._classification_confidence_level(confidence_score)

        if address_type == "random":
            advertising_pattern = "rotating"
        elif observation_count <= 1:
            advertising_pattern = "burst"
        elif stable_signal:
            advertising_pattern = "stable"
        else:
            advertising_pattern = "burst"

        if classified_type == "Mobile" or address_type == "random":
            movement = "mobile"
        elif public_mac and stable_signal:
            movement = "static"
        else:
            movement = "unknown"

        behavior = "rotating_address" if address_type == "random" else "stable_address"
        if classified_type == "Mobile" and known_vendor:
            ecosystem = f"{vendor} Ecosystem"
        elif classified_type == "IoT" and known_vendor:
            ecosystem = f"{vendor} IoT"
        elif classified_type == "IoT":
            ecosystem = "IoT Devices"
        elif classified_type == "Beacon":
            ecosystem = "Beacon Devices"
        else:
            ecosystem = "Unknown"

        ui_tone = "red"
        if protocol == "Zigbee (inferred)":
            ui_tone = "amber"
        elif classified_type == "Mobile":
            ui_tone = "cyan"
        elif classified_type == "IoT":
            ui_tone = "green"
        elif classified_type == "Beacon":
            ui_tone = "purple"

        risk_tier = str((device.get("risk") or {}).get("tier") or "baseline").lower()
        if risk_tier in {"critical", "high"}:
            risk_profile = "high"
        elif classified_type == "IoT" or protocol in {"BLE + Cloud", "Zigbee (inferred)"}:
            risk_profile = "medium"
        else:
            risk_profile = "low"

        tags = [
            vendor if known_vendor else "Unknown vendor",
            classified_type,
            protocol,
            behavior,
            movement,
            advertising_pattern,
        ]
        heuristic = {
            "vendor": vendor,
            "device_type": classified_type,
            "protocol": protocol,
            "confidence": confidence_score,
            "level": confidence_level,
            "behavior": behavior,
            "risk_profile": risk_profile,
            "ecosystem": ecosystem,
            "movement": movement,
            "advertising_pattern": advertising_pattern,
            "signal_spread_dbm": signal_spread,
            "signal_stable": stable_signal,
            "icon": self._classification_icon(device, classified_type),
            "ui_tone": ui_tone,
            "tags": tags,
        }
        matched_score = int(fingerprint_match.get("confidence") or 0)
        if not bool(fingerprint_match.get("matched")) or matched_score < 40:
            fallback_confidence = max(15, int(device.get("preclass_cluster_confidence") or 0), confidence_score)
            fallback_label = str(device.get("preclass_cluster_classification") or "unknown_candidate")
            fallback_meta = CLASSIFICATION_LABELS.get(fallback_label, CLASSIFICATION_LABELS.get("unknown_candidate", {}))
            heuristic["matched"] = False
            heuristic["matched_device"] = fallback_label
            heuristic["device_type"] = str(fallback_meta.get("device_type") or heuristic["device_type"] or "Unknown")
            heuristic["protocol"] = str(fallback_meta.get("protocol") or heuristic["protocol"] or "BLE")
            heuristic["ui_tone"] = str(fallback_meta.get("ui_tone") or heuristic["ui_tone"] or "neutral")
            heuristic["icon"] = str(fallback_meta.get("icon") or heuristic["icon"] or "❓")
            heuristic["confidence"] = fallback_confidence
            heuristic["level"] = self._classification_confidence_level(fallback_confidence)
            heuristic["classification"] = f"{heuristic['level']}_CONFIDENCE"
            heuristic["match_reasons"] = ["preclassification_cluster"]
            heuristic["source"] = "preclassification_cluster"
            heuristic["cluster_size"] = int(device.get("preclass_cluster_size") or 1)
            heuristic["behavior_profile"] = {
                "burst": observation_count <= 1,
                "interval_stable": stable_signal,
                "connect_attempts": 0,
            }
            return heuristic

        matched_vendor = str(fingerprint_match.get("vendor") or vendor or "Unknown")
        matched_type = str(fingerprint_match.get("classification_type") or classified_type or "Unknown")
        matched_protocol = str(fingerprint_match.get("protocol") or protocol or "Unknown")
        matched_behavior_profile = fingerprint_match.get("behavior_profile") if isinstance(fingerprint_match.get("behavior_profile"), dict) else {}
        merged_tags = sorted(set(tags).union(str(item) for item in (fingerprint_match.get("match_reasons") or []) if str(item).strip()))
        return {
            "vendor": matched_vendor,
            "device_type": matched_type,
            "protocol": matched_protocol,
            "confidence": max(confidence_score, matched_score),
            "level": str(fingerprint_match.get("level") or confidence_level),
            "behavior": behavior,
            "risk_profile": str(fingerprint_match.get("risk_profile") or risk_profile),
            "ecosystem": heuristic["ecosystem"] if matched_type == "Unknown" else (f"{matched_vendor} Ecosystem" if matched_type == "Mobile" else (f"{matched_vendor} IoT" if matched_type == "IoT" else heuristic["ecosystem"])),
            "movement": movement,
            "advertising_pattern": advertising_pattern,
            "signal_spread_dbm": signal_spread,
            "signal_stable": stable_signal,
            "icon": str(fingerprint_match.get("icon") or self._classification_icon(device, matched_type)),
            "ui_tone": str(fingerprint_match.get("ui_tone") or heuristic["ui_tone"]),
            "tags": merged_tags,
            "matched": True,
            "matched_device": str(fingerprint_match.get("device_name") or ""),
            "matched_model": str(fingerprint_match.get("model") or ""),
            "matched_category": str(fingerprint_match.get("category") or ""),
            "source": str(fingerprint_match.get("source") or ""),
            "notes": str(fingerprint_match.get("notes") or ""),
            "pairing_profile": str(fingerprint_match.get("pairing") or ""),
            "match_reasons": list(fingerprint_match.get("match_reasons") or []),
            "classification": str(fingerprint_match.get("classification") or f"{str(fingerprint_match.get('level') or confidence_level)}_CONFIDENCE"),
            "cluster_size": int(device.get("preclass_cluster_size") or int(fingerprint_match.get("cluster_size") or 1)),
            "behavior_profile": {
                "burst": bool(matched_behavior_profile.get("burst")),
                "interval_stable": bool(matched_behavior_profile.get("interval_stable") or stable_signal),
                "connect_attempts": int(matched_behavior_profile.get("connect_attempts") or 0),
            },
        }

    def _extract_rf_channel(self, decoded_frame: bytes, aa_index: int) -> int:
        prefix = decoded_frame[6:aa_index]
        for value in prefix:
            if value in self.DEFAULT_CHANNELS:
                return int(value)
        return self.DEFAULT_CHANNELS[0]

    def _decode_nordic_frame_observation(
        self,
        decoded_frame: bytes,
        sensor: Dict[str, Any],
        frame_index: int = 0,
        base_timestamp: float | None = None,
    ) -> Dict[str, Any] | None:
        aa_index = decoded_frame.find(self.NORDIC_ADV_ACCESS_ADDRESS)
        if aa_index < 0:
            return None
        ble_payload = decoded_frame[aa_index:]
        if len(ble_payload) < 9 or ble_payload[:4] != self.NORDIC_ADV_ACCESS_ADDRESS:
            return None
        header0 = ble_payload[4]
        header1 = ble_payload[5]
        pdu_type_code = header0 & 0x0F
        packet_type = self.BLE_PDU_TYPES.get(pdu_type_code)
        if not packet_type:
            return None
        payload_length = header1 & 0x3F
        body = ble_payload[6 : 6 + payload_length]
        if len(body) < 6:
            return None
        layout = self._choose_adv_layout(body)
        if layout is None:
            return None
        address_bytes, ad_payload = layout
        ad_data = self._decode_ad_structures(ad_payload)
        if ad_payload and int(ad_data.get("valid_structures") or 0) == 0:
            return None
        manufacturer_hex = str(ad_data.get("manufacturer_data_hex") or "")
        service_uuids = ad_data.get("service_uuids") or []
        name = self._sanitize_name(ad_data.get("name") or "Unknown BLE Device")
        if packet_type == "scan_rsp" and not manufacturer_hex and not service_uuids and name == "Unknown BLE Device":
            return None
        vendor = self._infer_vendor(ad_data, name)
        address_type = "random" if (header0 & 0x40) else "public"
        device_type, category = self._classify_asset(name, service_uuids, str(ad_data.get("appearance") or ""))
        timestamp = float(base_timestamp or time.time()) + (min(frame_index, 120) * 0.02)
        address = self._format_mac(address_bytes)
        asset_key = self._build_asset_key(address, address_type, name, vendor, device_type, service_uuids, manufacturer_hex)
        return {
            "timestamp": timestamp,
            "sensor_id": str(sensor.get("sensor_id") or "nr5-1"),
            "channel": self._extract_rf_channel(decoded_frame, aa_index),
            "address": address,
            "address_type": address_type,
            "name": name,
            "manufacturer": vendor,
            "vendor": vendor,
            "manufacturer_data_hash": sha1(manufacturer_hex.encode("utf-8")).hexdigest()[:16] if manufacturer_hex else "",
            "manufacturer_company_id": ad_data.get("company_id"),
            "manufacturer_data_prefix": manufacturer_hex[:10] if manufacturer_hex else "",
            "service_uuids": list(service_uuids),
            "service_uuid_signature": ",".join(sorted(service_uuids)),
            "service_data_uuids": sorted(
                str(item.get("uuid") or "")
                for item in (ad_data.get("service_data_16") or [])
                if str(item.get("uuid") or "").strip()
            ),
            "packet_type": packet_type,
            "packet_types": [packet_type],
            "packet_length": int(payload_length),
            "adv_flags": int(ad_data.get("flags")) if ad_data.get("flags") is not None else None,
            "ad_structure_count": int(ad_data.get("valid_structures") or 0),
            "connectable": packet_type in {"adv_ind", "adv_direct_ind", "adv_scan_ind"},
            "scannable": packet_type in {"adv_ind", "adv_scan_ind"},
            "scan_response_seen": packet_type == "scan_rsp",
            "observation_count": 1,
            "frame_count": 1,
            "channel_set": [self._extract_rf_channel(decoded_frame, aa_index)],
            "priority_class": category,
            "device_type": device_type,
            "appearance": ad_data.get("appearance") or "",
            "asset_key": asset_key,
            "identity_confidence": "high" if packet_type == "scan_rsp" or len(service_uuids) >= 2 else ("medium" if address_type == "public" or name != "Unknown BLE Device" or vendor != "Unknown" else "low"),
            "identity_reason": "scan_response_enriched" if packet_type == "scan_rsp" and self._identity_reason(address_type, name, vendor, service_uuids, manufacturer_hex) == "rotating_address_only" else self._identity_reason(address_type, name, vendor, service_uuids, manufacturer_hex),
            "vendor_confidence": self._vendor_confidence(ad_data, name, vendor),
            "vendor_source": self._vendor_source(ad_data, name, vendor),
            "category_confidence": self._category_confidence(name, service_uuids, category),
            "address_confidence": self._address_confidence(address_type, self._identity_reason(address_type, name, vendor, service_uuids, manufacturer_hex)),
            "stable_id": sha1(asset_key.encode("utf-8")).hexdigest()[:16],
            "tx_power": ad_data.get("tx_power"),
            "verdict": "Observed via Nordic BLE sniffer",
        }

    def _decode_nordic_observations(self, stream: bytes, sensor: Dict[str, Any]) -> tuple[list[Dict[str, Any]], int]:
        frames = self._split_nordic_frames(stream)
        observations: dict[str, Dict[str, Any]] = {}
        base_timestamp = time.time()
        for frame_index, decoded_frame in enumerate(frames):
            observation = self._decode_nordic_frame_observation(
                decoded_frame,
                sensor,
                frame_index=frame_index,
                base_timestamp=base_timestamp,
            )
            if observation is None:
                continue
            address = str(observation.get("address") or "")
            address_type = str(observation.get("address_type") or "unknown")
            observation_key = f"{address.lower()}|{address_type}"
            existing = observations.setdefault(
                observation_key,
                observation,
            )
            if existing is observation:
                continue
            existing["timestamp"] = max(float(existing.get("timestamp") or 0.0), float(observation.get("timestamp") or 0.0))
            existing["frame_count"] = int(existing.get("frame_count") or 0) + int(observation.get("frame_count") or 0)
            existing["observation_count"] = int(existing.get("observation_count") or 0) + int(observation.get("observation_count") or 0)
            if existing.get("channel") in {None, 0, ""}:
                existing["channel"] = observation.get("channel")
            if str(observation.get("packet_type") or "") != "scan_rsp":
                existing["packet_type"] = observation.get("packet_type")
            existing["connectable"] = bool(existing.get("connectable")) or bool(observation.get("connectable"))
            existing["scannable"] = bool(existing.get("scannable")) or bool(observation.get("scannable"))
            if str(observation.get("name") or "") != "Unknown BLE Device" and str(existing.get("name") or "") == "Unknown BLE Device":
                existing["name"] = observation.get("name")
            if str(observation.get("vendor") or "Unknown") != "Unknown" and str(existing.get("vendor") or "Unknown") == "Unknown":
                existing["vendor"] = observation.get("vendor")
                existing["manufacturer"] = observation.get("vendor")
            if str(observation.get("manufacturer_data_prefix") or "") and not str(existing.get("manufacturer_data_prefix") or ""):
                existing["manufacturer_data_prefix"] = observation.get("manufacturer_data_prefix")
            if str(observation.get("manufacturer_data_hash") or "") and not str(existing.get("manufacturer_data_hash") or ""):
                existing["manufacturer_data_hash"] = observation.get("manufacturer_data_hash")
            if existing.get("manufacturer_company_id") is None and observation.get("manufacturer_company_id") is not None:
                existing["manufacturer_company_id"] = observation.get("manufacturer_company_id")
            merged_service_uuids = sorted(set(existing.get("service_uuids") or []).union(observation.get("service_uuids") or []))
            existing["service_uuids"] = merged_service_uuids
            existing["service_uuid_signature"] = ",".join(merged_service_uuids)
            existing["ad_structure_count"] = max(int(existing.get("ad_structure_count") or 0), int(observation.get("ad_structure_count") or 0))
            if existing.get("adv_flags") is None and observation.get("adv_flags") is not None:
                existing["adv_flags"] = observation.get("adv_flags")
            if observation.get("appearance") and not str(existing.get("appearance") or ""):
                existing["appearance"] = observation.get("appearance") or ""
            if observation.get("tx_power") is not None and existing.get("tx_power") is None:
                existing["tx_power"] = observation.get("tx_power")
            channel_set = {int(item) for item in (existing.get("channel_set") or []) if item is not None}
            if observation.get("channel") is not None:
                channel_set.add(int(observation.get("channel")))
            existing["channel_set"] = sorted(channel_set)
            packet_types = {str(item) for item in (existing.get("packet_types") or []) if str(item).strip()}
            packet_types.update(str(item) for item in (observation.get("packet_types") or []) if str(item).strip())
            existing["packet_types"] = sorted(packet_types)
            existing["scan_response_seen"] = bool(existing.get("scan_response_seen")) or bool(observation.get("scan_response_seen"))
            service_data_uuids = {str(item) for item in (existing.get("service_data_uuids") or []) if str(item).strip()}
            service_data_uuids.update(str(item) for item in (observation.get("service_data_uuids") or []) if str(item).strip())
            existing["service_data_uuids"] = sorted(service_data_uuids)
            existing["identity_confidence"] = "high" if existing["scan_response_seen"] or len(merged_service_uuids) >= 2 else existing.get("identity_confidence")
            if existing["scan_response_seen"] and str(existing.get("identity_reason") or "") == "rotating_address_only":
                existing["identity_reason"] = "scan_response_enriched"
        return list(observations.values()), len(frames)

    def _run_nordic_serial_scan(
        self,
        sensor: Dict[str, Any],
        duration_seconds: int,
        stop_event: threading.Event | None = None,
        observation_sink: Callable[[Dict[str, Any]], Any] | None = None,
    ) -> Dict[str, Any]:
        probe = sensor.get("transport_probe") or {}
        path = str(sensor.get("scan_path") or "")
        if not path:
            return {
                "tool": "nrf52840",
                "ok": False,
                "detail": "no serial scan path is available for the selected sensor",
                "observation_count": 0,
                "raw_frame_count": 0,
                "transport": probe,
            }
        if probe.get("protocol") != "nordic_sniffer":
            return {
                "tool": "nrf52840",
                "ok": False,
                "detail": (
                    f"{probe.get('detail')}. BLE NR5 requires Nordic BLE Sniffer firmware for over-the-air scan collection."
                ),
                "observation_count": 0,
                "raw_frame_count": 0,
                "transport": probe,
            }
        if serial is None:
            return {
                "tool": "nrf52840",
                "ok": False,
                "detail": "pyserial is not installed, so the nRF52840 sniffer transport cannot be opened",
                "observation_count": 0,
                "raw_frame_count": 0,
                "transport": probe,
            }

        raw_frame_count = 0
        stream = bytearray()
        pending_frames = bytearray()
        handle = None
        try:
            handle = serial.Serial(path, baudrate=probe.get("baudrate") or 1000000, rtscts=True, timeout=0.1, write_timeout=0.2)
            if hasattr(handle, "reset_input_buffer"):
                handle.reset_input_buffer()
            try:
                self._nordic_sniffer_send_scan(handle)
            except Exception:
                pass
            started = time.monotonic()
            base_timestamp = time.time()
            streamed_frame_index = 0
            streamed_observations = 0
            while time.monotonic() - started < duration_seconds:
                if stop_event and stop_event.is_set():
                    break
                try:
                    chunk = handle.read(getattr(handle, "in_waiting", 0) or 1)
                except Exception:
                    if stream:
                        break
                    raise
                if not chunk:
                    continue
                stream.extend(chunk)
                if observation_sink is not None:
                    pending_frames.extend(chunk)
                    for decoded_frame in self._extract_nordic_frames_from_buffer(pending_frames):
                        live_observation = self._decode_nordic_frame_observation(
                            decoded_frame,
                            sensor,
                            frame_index=streamed_frame_index,
                            base_timestamp=base_timestamp,
                        )
                        streamed_frame_index += 1
                        if live_observation is None:
                            continue
                        observation_sink(live_observation)
                        streamed_observations += 1
            observations, raw_frame_count = self._decode_nordic_observations(bytes(stream), sensor)
            interrupted = bool(stop_event and stop_event.is_set())
            if observations:
                return {
                    "tool": "nrf52840",
                    "ok": True,
                    "detail": (
                        f"captured {len(observations)} BLE observation(s) from {raw_frame_count} Nordic sniffer frame(s) "
                        f"on {path} at {probe.get('baudrate')} baud"
                        f"{' before stop request' if interrupted else ''}"
                    ),
                    "observation_count": len(observations),
                    "streamed_observation_count": streamed_observations if observation_sink is not None else 0,
                    "raw_frame_count": raw_frame_count,
                    "interrupted": interrupted,
                    "transport": probe,
                    "observations": observations,
                }
            return {
                "tool": "nrf52840",
                "ok": raw_frame_count > 0,
                "detail": (
                    f"captured {raw_frame_count} Nordic sniffer frame(s) on {path} at {probe.get('baudrate')} baud, "
                    f"but none decoded into advertisement observations{' before stop request' if interrupted else ''}"
                ),
                "observation_count": 0,
                "streamed_observation_count": streamed_observations if observation_sink is not None else 0,
                "raw_frame_count": raw_frame_count,
                "interrupted": interrupted,
                "transport": probe,
                "observations": [],
            }
        except Exception as exc:
            return {
                "tool": "nrf52840",
                "ok": False,
                "detail": f"unable to open Nordic sniffer transport on {path}: {exc}",
                "observation_count": 0,
                "raw_frame_count": raw_frame_count,
                "transport": probe,
                "observations": [],
            }
        finally:
            try:
                if handle is not None:
                    handle.close()
            except Exception:
                pass

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                payload = json.loads(raw)
                if isinstance(payload, dict):
                    rows.append(payload)
        except Exception:
            return []
        return rows

    def _append_jsonl(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def _normalize_device_key(self, event: Dict[str, Any]) -> str:
        asset_key = str(event.get("asset_key") or "").strip().lower()
        address = str(event.get("address") or "").strip().lower()
        stable = str(event.get("stable_id") or "").strip().lower()
        manufacturer_hash = str(event.get("manufacturer_data_hash") or "").strip().lower()
        if asset_key:
            return asset_key
        if stable:
            return stable
        if address:
            return address
        if manufacturer_hash:
            return manufacturer_hash
        return f"unknown:{str(event.get('name') or 'device').strip().lower()}"

    def _risk_matches(self, event: Dict[str, Any]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        service_uuids = {str(item).lower() for item in (event.get("service_uuids") or [])}
        manufacturer = str(event.get("vendor") or event.get("manufacturer") or "").lower()
        categories = {str(item).lower() for item in (event.get("priority_classes") or [])}
        pairing_method = str(event.get("pairing_method") or "").lower()
        vendor_confidence = str(event.get("vendor_confidence") or "low").lower()
        bond_events = int(event.get("bond_events") or 0)
        repair_flags = int(event.get("repair_flags") or 0)
        pairing_failures = int(event.get("pairing_failures") or 0)
        silent_pairing_patterns = int(event.get("silent_pairing_patterns") or 0)
        writable_unauth = int(event.get("writable_unauth_count") or 0)
        sensitive_surface_count = int(event.get("sensitive_surface_count") or 0)
        meaningful_categories = {item for item in categories if item != "general"}

        for family in self._knowledge_base.get("vulnerability_families", []):
            triggers = family.get("triggers") or {}
            trigger_hit = False
            family_name = str(family.get("family") or "").strip().lower()
            if pairing_method and pairing_method in {str(item).lower() for item in triggers.get("pairing_methods", [])}:
                trigger_hit = True
            if service_uuids.intersection({str(item).lower() for item in triggers.get("service_uuids", [])}):
                trigger_hit = True
            trigger_vendors = {str(item).lower() for item in triggers.get("vendors", [])}
            if manufacturer and manufacturer in trigger_vendors:
                trigger_hit = True
            if categories.intersection({str(item).lower() for item in triggers.get("priority_classes", [])}):
                trigger_hit = True
            if family_name == "weak bond reuse / re-pair abuse":
                trigger_hit = trigger_hit and bool(bond_events or repair_flags or pairing_failures or silent_pairing_patterns)
            elif family_name == "gatt control surface exposure":
                trigger_hit = trigger_hit and bool(writable_unauth or sensitive_surface_count)
            elif family_name == "firmware-family bluetooth exposure":
                trigger_hit = trigger_hit and manufacturer not in {"", "unknown", "generic"} and vendor_confidence in {"medium", "high"}
            elif family_name == "just works trust weakness":
                trigger_hit = trigger_hit and bool(pairing_method)
            if trigger_hit and not (
                manufacturer == "unknown"
                and not pairing_method
                and not service_uuids
                and not meaningful_categories
            ):
                matches.append(
                    {
                        "family": family.get("family") or "Bluetooth Exposure",
                        "severity": family.get("severity") or "medium",
                        "detail": family.get("detail") or "",
                        "preconditions": family.get("preconditions") or [],
                    }
                )
        return matches

    def _score_device(self, aggregate: Dict[str, Any]) -> Dict[str, Any]:
        pairings = aggregate.get("pairing_methods") or []
        just_works = any("just works" in str(item).lower() for item in pairings)
        writable_unauth = bool(aggregate.get("writable_unauth_count"))
        cve_count = len(aggregate.get("vulnerability_matches") or [])
        priority_class = aggregate.get("priority_class") or "general"
        sensitive = aggregate.get("sensitive_surface_count") or 0

        score = 20
        if just_works:
            score += 20
        if writable_unauth:
            score += 20
        score += min(25, cve_count * 7)
        score += min(20, int(sensitive) * 4)
        if priority_class in {"medical_device", "vehicle", "smart_lock", "hid", "industrial_gateway"}:
            score += 15
        return {
            "score": min(100, score),
            "tier": "critical" if score >= 80 else ("high" if score >= 60 else ("moderate" if score >= 40 else "baseline")),
        }

    def _task_state_map(self) -> Dict[str, Dict[str, Any]]:
        payload = self._read_json_object(self.task_state_path)
        tasks = payload.get("tasks")
        return tasks if isinstance(tasks, dict) else {}

    def _save_task_state_map(self, tasks: Dict[str, Dict[str, Any]]) -> None:
        self._write_json_object(self.task_state_path, {"tasks": tasks, "updated_at": time.time()})

    def _workflow_descriptor(self, workflow: str) -> Dict[str, str]:
        normalized = str(workflow or "monitor").strip().lower()
        if normalized == "validate":
            return {
                "workflow": "validate",
                "state": "validation_ready",
                "label": "Validate",
                "summary": "Approved lab validation target.",
            }
        if normalized == "assess":
            return {
                "workflow": "assess",
                "state": "assessment_pending",
                "label": "Assess",
                "summary": "Red-team assessment target.",
            }
        return {
            "workflow": "monitor",
            "state": "monitoring",
            "label": "Monitor",
            "summary": "Passive monitoring target.",
        }

    def assign_workflow(self, device_key: str, workflow: str, notes: str = "", source: str = "manual") -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"status": "error", "error": "device_key is required"}
        descriptor = self._workflow_descriptor(workflow)
        tasks = self._task_state_map()
        now = time.time()
        tasks[normalized_key] = {
            "device_key": normalized_key,
            "workflow": descriptor["workflow"],
            "state": descriptor["state"],
            "label": descriptor["label"],
            "summary": descriptor["summary"],
            "notes": str(notes or "").strip(),
            "source": str(source or "manual").strip().lower(),
            "updated_at": now,
            "validation": tasks.get(normalized_key, {}).get("validation") if isinstance(tasks.get(normalized_key, {}).get("validation"), dict) else {},
            "active_validation": tasks.get(normalized_key, {}).get("active_validation") if isinstance(tasks.get(normalized_key, {}).get("active_validation"), dict) else {},
            "validation_suite": tasks.get(normalized_key, {}).get("validation_suite") if isinstance(tasks.get(normalized_key, {}).get("validation_suite"), dict) else {},
            "validation_run": tasks.get(normalized_key, {}).get("validation_run") if isinstance(tasks.get(normalized_key, {}).get("validation_run"), dict) else {},
            "gatt_test": tasks.get(normalized_key, {}).get("gatt_test") if isinstance(tasks.get(normalized_key, {}).get("gatt_test"), dict) else {},
            "validation_history": list(tasks.get(normalized_key, {}).get("validation_history") or []),
        }
        self._save_task_state_map(tasks)
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": now,
                "event_type": "workflow_assignment",
                "device_key": normalized_key,
                "workflow": descriptor["workflow"],
                "state": descriptor["state"],
                "notes": str(notes or "").strip(),
                "source": str(source or "manual").strip().lower(),
            },
        )
        return {"status": "assigned", "task": tasks[normalized_key]}

    def record_validation_result(
        self,
        device_key: str,
        pairable_verdict: str = "",
        legacy_pin_risk: str = "",
        manual_result: str = "",
        notes: str = "",
    ) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"status": "error", "error": "device_key is required"}
        tasks = self._task_state_map()
        existing = tasks.get(normalized_key) or self._workflow_descriptor("validate")
        now = time.time()
        validation = {
            "pairable_verdict": str(pairable_verdict or "unknown").strip().lower(),
            "legacy_pin_risk": str(legacy_pin_risk or "unknown").strip().lower(),
            "manual_result": str(manual_result or "unknown").strip().lower(),
            "notes": str(notes or "").strip(),
            "updated_at": now,
        }
        task = {
            "device_key": normalized_key,
            "workflow": existing.get("workflow") or "validate",
            "state": "validated" if validation["manual_result"] in {"paired", "rejected"} else "validation_ready",
            "label": existing.get("label") or "Validate",
            "summary": existing.get("summary") or "Approved lab validation target.",
            "notes": str(notes or existing.get("notes") or "").strip(),
            "source": existing.get("source") or "manual",
            "updated_at": now,
            "validation": validation,
            "active_validation": existing.get("active_validation") if isinstance(existing.get("active_validation"), dict) else {},
            "validation_suite": existing.get("validation_suite") if isinstance(existing.get("validation_suite"), dict) else {},
            "validation_run": existing.get("validation_run") if isinstance(existing.get("validation_run"), dict) else {},
            "gatt_test": existing.get("gatt_test") if isinstance(existing.get("gatt_test"), dict) else {},
            "validation_history": list(existing.get("validation_history") or []),
        }
        tasks[normalized_key] = task
        self._save_task_state_map(tasks)
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": now,
                "event_type": "validation_result",
                "device_key": normalized_key,
                "manual_result": validation["manual_result"],
                "pairable_verdict": validation["pairable_verdict"],
                "legacy_pin_risk": validation["legacy_pin_risk"],
            },
        )
        return {"status": "recorded", "task": task}

    def get_tasks(self) -> Dict[str, Any]:
        tasks = list(self._task_state_map().values())
        tasks.sort(key=lambda item: float(item.get("updated_at") or 0), reverse=True)
        return {"count": len(tasks), "tasks": tasks}

    def _merge_task_state(self, device: Dict[str, Any]) -> Dict[str, Any]:
        task = self._task_state_map().get(str(device.get("device_key") or "").lower()) or {}
        if task:
            device["workflow"] = task.get("workflow") or "monitor"
            device["workflow_state"] = task.get("state") or "monitoring"
            device["workflow_label"] = task.get("label") or "Monitor"
            device["workflow_summary"] = task.get("summary") or "Passive monitoring target."
            device["workflow_notes"] = task.get("notes") or ""
            device["workflow_source"] = task.get("source") or "manual"
            device["workflow_updated_at"] = task.get("updated_at")
            validation = task.get("validation") if isinstance(task.get("validation"), dict) else {}
            device["validation"] = validation
            device["active_validation"] = task.get("active_validation") if isinstance(task.get("active_validation"), dict) else {}
            device["validation_suite"] = task.get("validation_suite") if isinstance(task.get("validation_suite"), dict) else {}
            device["validation_run"] = task.get("validation_run") if isinstance(task.get("validation_run"), dict) else {}
            device["gatt_test"] = task.get("gatt_test") if isinstance(task.get("gatt_test"), dict) else {}
            device["validation_history"] = list(task.get("validation_history") or [])
        else:
            default_task = self._workflow_descriptor("monitor")
            device["workflow"] = default_task["workflow"]
            device["workflow_state"] = default_task["state"]
            device["workflow_label"] = default_task["label"]
            device["workflow_summary"] = default_task["summary"]
            device["workflow_notes"] = ""
            device["workflow_source"] = "default"
            device["workflow_updated_at"] = None
            device["validation"] = {}
            device["active_validation"] = {}
            device["validation_suite"] = {}
            device["validation_run"] = {}
            device["gatt_test"] = {}
            device["validation_history"] = []
        device["validation_ready"] = device["workflow"] == "validate" and bool(device.get("connectable"))
        return device

    def _promote_scan_assets(self, devices: List[Dict[str, Any]]) -> int:
        tasks = self._task_state_map()
        now = time.time()
        promoted = 0
        descriptor = self._workflow_descriptor("validate")
        for device in devices:
            device_key = str(device.get("device_key") or "").strip().lower()
            if not device_key:
                continue
            existing = tasks.get(device_key) or {}
            existing_workflow = str(existing.get("workflow") or "").strip().lower()
            existing_source = str(existing.get("source") or "").strip().lower()
            if existing_workflow == "monitor" and existing_source == "manual":
                continue
            tasks[device_key] = {
                "device_key": device_key,
                "workflow": descriptor["workflow"],
                "state": descriptor["state"],
                "label": descriptor["label"],
                "summary": "Auto-promoted after scan for assessment and lab validation review.",
                "notes": str(existing.get("notes") or ""),
                "source": "auto_scan",
                "updated_at": now,
                "validation": existing.get("validation") if isinstance(existing.get("validation"), dict) else {},
                "active_validation": existing.get("active_validation") if isinstance(existing.get("active_validation"), dict) else {},
                "validation_suite": existing.get("validation_suite") if isinstance(existing.get("validation_suite"), dict) else {},
                "validation_run": existing.get("validation_run") if isinstance(existing.get("validation_run"), dict) else {},
                "gatt_test": existing.get("gatt_test") if isinstance(existing.get("gatt_test"), dict) else {},
                "validation_history": list(existing.get("validation_history") or []),
            }
            promoted += 1
        if promoted:
            self._save_task_state_map(tasks)
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": now,
                    "event_type": "scan_auto_promote",
                    "workflow": descriptor["workflow"],
                    "state": descriptor["state"],
                    "promoted_count": promoted,
                },
            )
        return promoted

    def _infer_target_pack(self, device: Dict[str, Any]) -> Dict[str, Any]:
        category = str(device.get("priority_class") or "general")
        pack = dict(self.TARGET_CLASS_PACKS.get(category, self.TARGET_CLASS_PACKS["general"]))
        service_uuids = {str(item).lower() for item in (device.get("service_uuids") or [])}
        vendor = str(device.get("vendor") or "Unknown")
        name = str(device.get("name") or "Unknown BLE Device")
        exploit_families = list(pack.get("exploit_families") or [])
        if "1812" in service_uuids and "hid_impersonation" not in exploit_families:
            exploit_families.append("hid_impersonation")
        if "fe2c" in service_uuids and "tracking_abuse" not in exploit_families:
            exploit_families.append("tracking_abuse")
        if vendor == "Apple" and "fast_pair_abuse" not in exploit_families and category == "audio":
            exploit_families.append("ecosystem_pairing_abuse")
        if vendor == "Samsung" and category in {"wearable", "audio"} and "tracking_abuse" not in exploit_families:
            exploit_families.append("tracking_abuse")
        if "tile" in name.lower() and "tracking_abuse" not in exploit_families:
            exploit_families.append("tracking_abuse")
        return {
            "likely_family": pack.get("family") or "generic_ble",
            "likely_product_class": pack.get("product_class") or "general",
            "exploit_families": sorted(set(exploit_families)),
        }

    def _tracking_risk(self, device: Dict[str, Any]) -> str:
        service_uuids = {str(item).lower() for item in (device.get("service_uuids") or [])}
        category = str(device.get("priority_class") or "general")
        vendor = str(device.get("vendor") or "Unknown")
        if category in {"audio", "wearable"} and vendor in {"Apple", "Samsung", "Tile", "Google"}:
            return "high"
        if "fe2c" in service_uuids or "fd6f" in service_uuids:
            return "high"
        if str(device.get("address_type") or "") == "public":
            return "medium"
        return "low"

    def _pairable_verdict(self, device: Dict[str, Any]) -> Dict[str, str]:
        validation = device.get("validation") if isinstance(device.get("validation"), dict) else {}
        active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        validation_verdict = str(validation.get("pairable_verdict") or "").strip().lower()
        if validation_verdict in {"yes", "no"}:
            return {
                "pairable": validation_verdict,
                "pairable_confidence": "high",
                "pairable_reason": "lab_validation_override",
            }
        active_connect = str(active_validation.get("connect_result") or "").strip().lower()
        if active_connect in {"connected", "paired"}:
            return {
                "pairable": "yes",
                "pairable_confidence": "high",
                "pairable_reason": "active_connect_success",
            }
        if active_connect == "failed":
            return {
                "pairable": "no",
                "pairable_confidence": "medium",
                "pairable_reason": "active_connect_failed",
            }
        if bool(device.get("connectable")):
            return {
                "pairable": "yes",
                "pairable_confidence": "medium",
                "pairable_reason": "connectable_advertising_seen",
            }
        return {
            "pairable": "no",
            "pairable_confidence": "medium",
            "pairable_reason": "nonconnectable_advertising_only",
        }

    def _behavioral_anomalies(self, device: Dict[str, Any]) -> List[str]:
        anomalies: List[str] = []
        if int(device.get("identity_variants") or 0) > 1:
            anomalies.append("identity_drift")
        if int(device.get("service_signatures") or 0) > 1:
            anomalies.append("service_drift")
        if int(device.get("pairing_failures") or 0) > 0:
            anomalies.append("pairing_failure_seen")
        if int(device.get("repair_flags") or 0) > 0 or int(device.get("silent_pairing_patterns") or 0) > 0:
            anomalies.append("trust_lifecycle_change")
        return anomalies

    def _variance(self, values: List[float]) -> float:
        cleaned = [float(item) for item in (values or [])]
        if len(cleaned) < 2:
            return 0.0
        mean = sum(cleaned) / len(cleaned)
        return sum((value - mean) ** 2 for value in cleaned) / len(cleaned)

    def _rf_quality(self, device: Dict[str, Any]) -> Dict[str, Any]:
        observation_count = int(device.get("observation_count") or 0)
        event_count = int(device.get("event_count") or 0)
        avg_rssi = device.get("avg_rssi")
        dwell_seconds = float(device.get("dwell_seconds") or 0.0)
        interval_samples = [float(item) for item in (device.get("advertising_interval_samples") or []) if item is not None]
        freshness_seconds = max(0.0, time.time() - float(device.get("last_seen") or time.time()))
        interval_variance = self._variance(interval_samples)
        service_uuids = [str(item).strip() for item in (device.get("service_uuids") or []) if str(item).strip()]
        service_data_uuids = [str(item).strip() for item in (device.get("service_data_uuids") or []) if str(item).strip()]
        manufacturer_prefix = str(device.get("manufacturer_data_prefix") or "").strip().lower()
        company_id = device.get("manufacturer_company_id")
        name = str(device.get("name") or "").strip()
        scan_response_seen = bool(device.get("scan_response_seen"))
        channel_count = len(device.get("channels_seen") or [])
        classification = device.get("classification") if isinstance(device.get("classification"), dict) else {}
        has_anchor = bool(service_uuids or service_data_uuids or manufacturer_prefix or company_id not in {None, ""} or (name and name != "Unknown BLE Device"))

        score = 0
        reasons: List[str] = []
        if observation_count >= 5:
            score += 35
            reasons.append(f"{observation_count} observations")
        elif observation_count >= 3:
            score += 24
            reasons.append(f"{observation_count} observations")
        elif observation_count >= 2:
            score += 14
            reasons.append("limited repeat sightings")
        else:
            score += 4
            reasons.append("single sighting")

        if avg_rssi is not None:
            try:
                avg_rssi_value = float(avg_rssi)
                if avg_rssi_value >= -72:
                    score += 30
                    reasons.append(f"strong RSSI {int(avg_rssi_value)} dBm")
                elif avg_rssi_value >= -84:
                    score += 18
                    reasons.append(f"usable RSSI {int(avg_rssi_value)} dBm")
                else:
                    score += 6
                    reasons.append(f"weak RSSI {int(avg_rssi_value)} dBm")
            except Exception:
                reasons.append("RSSI unavailable")
        else:
            reasons.append("RSSI unavailable")

        if dwell_seconds >= 10 or observation_count >= 4:
            score += 20
            reasons.append("stable dwell")
        elif dwell_seconds >= 3:
            score += 10
            reasons.append("short dwell")
        elif observation_count >= 3:
            score += 11
            reasons.append("repeat burst captured")
        else:
            score += 4
            reasons.append("brief presence")

        if len(interval_samples) >= 2:
            if interval_variance <= 25000:
                score += 15
                reasons.append("interval stable")
            elif interval_variance <= 120000:
                score += 9
                reasons.append("interval moderately stable")
            else:
                reasons.append("interval unstable")
        elif observation_count >= 3:
            score += 8
            reasons.append("repeat sightings without interval baseline")
        else:
            reasons.append("limited interval evidence")

        if has_anchor:
            score += 12
            reasons.append("identity anchor present")
        elif int(classification.get("confidence") or 0) >= 60:
            score += 8
            reasons.append("classifier confidence anchor")

        if scan_response_seen:
            score += 8
            reasons.append("scan response enriched")
        if channel_count >= 2:
            score += 6
            reasons.append(f"{channel_count} adv channels seen")
        elif event_count >= 2 and observation_count >= 3:
            score += 3
            reasons.append("multi-event visibility")

        if freshness_seconds <= 120:
            score += 10
            reasons.append("fresh RF activity")
        elif freshness_seconds <= 300:
            score += 6
            reasons.append("recent RF activity")
        else:
            score += 2
            reasons.append("stale RF activity")

        label = "WEAK"
        if score >= 70:
            label = "STRONG"
        elif score >= 30:
            label = "MEDIUM"
        return {
            "score": max(5, min(95, int(score))),
            "label": label,
            "reasons": reasons[:5],
            "freshness_seconds": round(freshness_seconds, 1),
            "interval_variance": round(interval_variance, 1),
            "stable": bool(label in {"STRONG", "MEDIUM"} and (not interval_samples or interval_variance <= 120000)),
        }

    def _auditability_gate(self, device: Dict[str, Any]) -> Dict[str, Any]:
        rf_quality = self._rf_quality(device)
        connectable = bool(device.get("connectable"))
        address_type = str(device.get("address_type") or "unknown").strip().lower()
        observation_count = int(device.get("observation_count") or 0)
        name = str(device.get("name") or "").strip()
        service_uuids = [str(item).strip() for item in (device.get("service_uuids") or []) if str(item).strip()]
        service_data_uuids = [str(item).strip() for item in (device.get("service_data_uuids") or []) if str(item).strip()]
        manufacturer_prefix = str(device.get("manufacturer_data_prefix") or "").strip().lower()
        company_id = device.get("manufacturer_company_id")
        classification = device.get("classification") if isinstance(device.get("classification"), dict) else {}
        classification_confidence = int(classification.get("confidence") or 0)
        classified_type = str(classification.get("device_type") or "").strip()
        matched_device = str(classification.get("matched_device") or "").strip()
        classification_source = str(classification.get("source") or "").strip().lower()
        has_identity_anchor = bool(
            service_uuids
            or service_data_uuids
            or manufacturer_prefix
            or company_id not in {None, ""}
            or (name and name != "Unknown BLE Device")
        )
        named_or_fingerprinted = bool(
            has_identity_anchor
            and (
                (
                    matched_device not in {"", "Unknown BLE Device", "IoT Candidate", "mobile_privacy_device", "beacon_device", "unknown_candidate", "iot_candidate"}
                    and classification_source not in {"quick_rule", "provisional_cluster", "preclassification_cluster"}
                )
                or (
                    classification_confidence >= 70
                    and classification_source not in {"quick_rule", "provisional_cluster", "preclassification_cluster"}
                )
            )
        )
        privacy_mobile = bool(
            address_type == "random"
            and classified_type == "Mobile"
            and company_id in {76, 117, 224, 6}
            and observation_count <= 2
        )

        if not connectable:
            return {
                "state": "NOT_AUDITABLE",
                "reason": "broadcast-only BLE device does not expose an active audit path",
                "action": "Ignore for active testing and retain passive evidence only.",
                "allow_active_testing": False,
                "rf_quality": rf_quality,
            }

        if privacy_mobile:
            return {
                "state": "NOT_AUDITABLE",
                "reason": "privacy-rotating personal device is unlikely to yield stable audit evidence",
                "action": "Ignore for active testing and retain passive evidence only.",
                "allow_active_testing": False,
                "rf_quality": rf_quality,
            }

        if address_type == "random" and observation_count <= 2 and not has_identity_anchor:
            return {
                "state": "NOT_AUDITABLE",
                "reason": "device uses BLE privacy rotation with too little stable identity evidence",
                "action": "Ignore for active testing and continue passive clustering if this target matters.",
                "allow_active_testing": False,
                "rf_quality": rf_quality,
            }

        if named_or_fingerprinted and connectable and classified_type != "Beacon":
            return {
                "state": "AUDITABLE",
                "reason": "connectable device has a stable fingerprint or named identity suitable for audit attempts",
                "action": "Run Hard BLE Test while the device remains active.",
                "allow_active_testing": True,
                "rf_quality": rf_quality,
            }

        if rf_quality["label"] == "WEAK" and not has_identity_anchor:
            return {
                "state": "LIMITED",
                "reason": "RF quality is too weak for reliable materialization or validation",
                "action": "Move closer, rescan, and wait for repeated observations before testing.",
                "allow_active_testing": False,
                "rf_quality": rf_quality,
            }

        if observation_count <= 1 and not has_identity_anchor:
            return {
                "state": "LIMITED",
                "reason": "device lacks enough repeated presence or fingerprint data",
                "action": "Rescan until the device is seen multiple times or exposes UUID/name/manufacturer evidence.",
                "allow_active_testing": False,
                "rf_quality": rf_quality,
            }

        if connectable and (observation_count >= 2 or has_identity_anchor or classification_confidence >= 55):
            return {
                "state": "AUDITABLE",
                "reason": "stable connectable device with enough identity evidence for host-side auditing",
                "action": "Run Active Test or Hard BLE Test.",
                "allow_active_testing": True,
                "rf_quality": rf_quality,
            }

        return {
            "state": "LIMITED",
            "reason": "device is connectable but still lacks stable audit conditions",
            "action": "Collect more observations and retry once RF quality improves.",
            "allow_active_testing": False,
            "rf_quality": rf_quality,
        }

    def _validation_failure_reason(self, device: Dict[str, Any], active_validation: Dict[str, Any] | None = None) -> Dict[str, str]:
        gate = self._auditability_gate(device)
        if gate["state"] != "AUDITABLE":
            return {"reason": gate["reason"], "action": gate["action"]}

        active = active_validation if isinstance(active_validation, dict) else {}
        resolution = active.get("resolution") if isinstance(active.get("resolution"), dict) else {}
        blocked_state = active.get("blocked_state") if isinstance(active.get("blocked_state"), dict) else {}
        connect_result = str(active.get("connect_result") or "").lower()
        resolution_state = str((resolution or {}).get("state") or device.get("resolution_state") or "").lower()
        service_count = int(active.get("service_count") or 0)
        characteristic_count = int(active.get("characteristic_count") or 0)
        pairing = active.get("pairing_transcript") if isinstance(active.get("pairing_transcript"), dict) else {}
        prompt_seen = bool(pairing.get("prompt_seen"))
        if blocked_state.get("reason"):
            return {
                "reason": str(blocked_state.get("reason") or ""),
                "action": str(blocked_state.get("next_action") or "Retry with stronger evidence."),
            }

        if resolution_state in {"observed", "candidate", "candidate_only", "failed"}:
            return {
                "reason": "target is not visible to BlueZ as a stable Device1 object",
                "action": "Run a fresh scan while the device is active and retry materialization immediately.",
            }
        if connect_result in {"blocked_unresolved", "materialized_only"}:
            return {
                "reason": "host target materialized incompletely and did not reach a usable connect path",
                "action": "Retry while the device is actively advertising and closer to the adapter.",
            }
        if prompt_seen and connect_result not in {"connected", "paired"}:
            return {
                "reason": "pairing requires user interaction on the target device",
                "action": "Unlock or confirm pairing on the device, then rerun the audit.",
            }
        if active.get("attempted") and service_count == 0 and characteristic_count == 0:
            return {
                "reason": "no GATT services were exposed during the validation attempt",
                "action": "Retry after pairing or while the device is in setup / pairing mode.",
            }
        return {
            "reason": "target is ready for deeper BLE validation",
            "action": "Run Hard BLE Test.",
        }

    def _priority_score(self, device: Dict[str, Any]) -> Dict[str, Any]:
        gate = self._auditability_gate(device)
        classification = device.get("classification") if isinstance(device.get("classification"), dict) else {}
        resolution_state = str(device.get("resolution_state") or "").lower()
        score = 0
        if gate["state"] == "AUDITABLE":
            score += 45
        elif gate["state"] == "LIMITED":
            score += 18
        rf_label = str((gate.get("rf_quality") or {}).get("label") or "WEAK")
        if rf_label == "STRONG":
            score += 25
        elif rf_label == "MEDIUM":
            score += 12
        score += min(20, int(classification.get("confidence") or 0) // 5)
        if bool(device.get("connectable")):
            score += 10
        if resolution_state in {"materialized", "validation_ready"}:
            score += 10
        elif resolution_state in {"candidate", "candidate_only"}:
            score += 4
        recommended = bool(gate["state"] == "AUDITABLE" and rf_label == "STRONG" and score >= 78)
        return {
            "score": max(0, min(100, score)),
            "recommended": recommended,
            "label": "RECOMMENDED TARGET" if recommended else "STANDARD TARGET",
        }

    def _device_evidence_timeline(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        first_seen = float(device.get("first_seen") or 0)
        last_seen = float(device.get("last_seen") or 0)
        gate = self._auditability_gate(device)
        resolution_state = str(device.get("resolution_state") or "")
        active = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        suite = device.get("validation_suite") if isinstance(device.get("validation_suite"), dict) else {}
        gatt = device.get("gatt_test") if isinstance(device.get("gatt_test"), dict) else {}

        if first_seen:
            items.append({"timestamp": first_seen, "event": "detection", "detail": "device first seen via RF collection"})
        if device.get("logical_device_id") or device.get("preclass_cluster_id"):
            items.append({
                "timestamp": last_seen or first_seen,
                "event": "clustering",
                "detail": f"clustered as {device.get('logical_device_id') or device.get('preclass_cluster_id')}",
            })
        items.append({
            "timestamp": last_seen or first_seen or time.time(),
            "event": "auditability",
            "detail": f"{gate['state']} · {gate['reason']}",
        })
        resolution_ts = device.get("resolution_last_success") or device.get("last_seen")
        if resolution_state:
            items.append({
                "timestamp": float(resolution_ts or time.time()),
                "event": "materialization",
                "detail": f"{resolution_state} · {device.get('resolution_summary') or 'no detail'}",
            })
        blocked_state = active.get("blocked_state") if isinstance(active.get("blocked_state"), dict) else {}
        if blocked_state.get("reason"):
            items.append({
                "timestamp": float(active.get("tested_at") or last_seen or time.time()),
                "event": "blocked",
                "detail": f"{blocked_state.get('stage') or 'validation'} · {blocked_state.get('reason') or 'blocked'}",
            })
        if active.get("tested_at"):
            items.append({
                "timestamp": float(active.get("tested_at") or time.time()),
                "event": "active_validation",
                "detail": f"{active.get('connect_result') or 'unknown'} · {active.get('detail') or ''}",
            })
        if suite.get("updated_at"):
            items.append({
                "timestamp": float(suite.get("updated_at") or time.time()),
                "event": "validation_suite",
                "detail": f"{suite.get('status') or 'unknown'} · {suite.get('scenario_count') or 0} scenarios",
            })
        if gatt.get("tested_at"):
            items.append({
                "timestamp": float(gatt.get("tested_at") or time.time()),
                "event": "gatt_discovery",
                "detail": f"{gatt.get('status') or 'pending'} · {gatt.get('service_count') or 0} svc · {gatt.get('characteristic_count') or 0} char",
            })
        if str(((gatt.get("gatt_differential") or {}).get("summary")) or "").strip():
            items.append({
                "timestamp": float(gatt.get("tested_at") or time.time()),
                "event": "gatt_diff",
                "detail": str((gatt.get("gatt_differential") or {}).get("summary") or ""),
            })
        state_history = list(device.get("state_history") or [])
        for entry in state_history[-4:]:
            if not isinstance(entry, dict):
                continue
            items.append({
                "timestamp": float(entry.get("timestamp") or time.time()),
                "event": "state",
                "detail": str(entry.get("state") or "unknown"),
            })
        items.sort(key=lambda item: float(item.get("timestamp") or 0))
        return items[-12:]

    def _blocked_validation_result(
        self,
        device: Dict[str, Any],
        *,
        tested_at: float,
        connect_result: str,
        detail: str,
        next_best_action: str,
        error_code: str,
    ) -> Dict[str, Any]:
        gate = self._auditability_gate(device)
        return {
            "device_key": str(device.get("device_key") or "").strip().lower(),
            "tested_at": tested_at,
            "attempted": False,
            "outcome": "blocked",
            "connect_result": connect_result,
            "detail": detail,
            "operator_summary": detail,
            "next_best_action": next_best_action,
            "failure_reason": detail,
            "action_guidance": next_best_action,
            "trust_state": "blocked",
            "gatt_state": "blocked",
            "info": {},
            "services_resolved": False,
            "service_count": 0,
            "characteristic_count": 0,
            "readable_count": 0,
            "writable_count": 0,
            "notify_count": 0,
            "unauth_readable_count": 0,
            "unauth_writable_count": 0,
            "attribute_lines": [],
            "services": [],
            "errors": [error_code, detail],
            "raw_output": "",
            "pairing_transcript": {
                "challenge_type": "unknown",
                "prompt_seen": False,
                "paired_after": False,
                "trusted_after": False,
                "services_resolved": False,
                "summary": detail,
            },
            "validation_confidence": {"score": 0, "level": "low", "summary": "low confidence · validation blocked"},
            "reconnect_probe": {
                "attempted": False,
                "result": connect_result,
                "detail": detail,
                "connect_attempts": 0,
                "successful_attempts": 0,
            },
            "harder_test_results": [],
            "blocked_state": self._blocked_state_detail(
                code=error_code,
                stage="validation",
                reason=detail,
                evidence=list((gate.get("rf_quality") or {}).get("reasons") or []),
                next_action=next_best_action,
            ),
            "resolution": self._resolve_target_materialization(device) if gate["state"] == "AUDITABLE" else {},
        }

    def _auto_validation_summary(self, device: Dict[str, Any]) -> Dict[str, Any]:
        validation = device.get("validation") if isinstance(device.get("validation"), dict) else {}
        active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        validation_suite = device.get("validation_suite") if isinstance(device.get("validation_suite"), dict) else {}
        auditability = device.get("auditability") if isinstance(device.get("auditability"), dict) else self._auditability_gate(device)
        rf_quality = device.get("rf_quality") if isinstance(device.get("rf_quality"), dict) else self._rf_quality(device)
        steps: List[Dict[str, str]] = []

        steps.append(
            {
                "id": "auditability",
                "label": "Auditability",
                "status": "pass" if str(auditability.get("state") or "") == "AUDITABLE" else ("weak" if str(auditability.get("state") or "") == "LIMITED" else "fail"),
                "detail": f"{auditability.get('state') or 'UNKNOWN'} · {auditability.get('reason') or 'no reason'}",
            }
        )

        steps.append(
            {
                "id": "rf",
                "label": "RF",
                "status": "pass" if str(rf_quality.get("label") or "") == "STRONG" else ("weak" if str(rf_quality.get("label") or "") == "MEDIUM" else "fail"),
                "detail": f"{rf_quality.get('label') or 'WEAK'} · {rf_quality.get('score') or 0}",
            }
        )

        address_ok = str(device.get("address_confidence") or "low") in {"high", "medium"}
        steps.append(
            {
                "id": "identity",
                "label": "Identity",
                "status": "pass" if address_ok else "weak",
                "detail": f"{device.get('address_type') or 'unknown'} · {device.get('identity_reason') or 'unknown_reason'}",
            }
        )

        vendor_ok = str(device.get("vendor_source") or "unknown") != "unknown" and str(device.get("vendor") or "Unknown") != "Unknown"
        steps.append(
            {
                "id": "vendor",
                "label": "Vendor",
                "status": "pass" if vendor_ok else "unknown",
                "detail": f"{device.get('vendor') or 'Unknown'} via {device.get('vendor_source') or 'unknown'}",
            }
        )

        pairable = str(device.get("pairable") or "no").lower()
        pair_status = "pass" if pairable == "yes" else "fail"
        if validation and str(validation.get("manual_result") or "").lower() in {"paired", "rejected"}:
            pair_status = "pass"
        steps.append(
            {
                "id": "connect",
                "label": "Connect",
                "status": pair_status,
                "detail": f"{pairable} · {device.get('pairable_reason') or 'pairing_state_unknown'}",
            }
        )

        active_attempted = bool(active_validation.get("attempted"))
        service_count = int(active_validation.get("service_count") or 0)
        characteristic_count = int(active_validation.get("characteristic_count") or 0)
        gatt_status = "unknown"
        if active_attempted:
            gatt_status = "pass" if (service_count > 0 or characteristic_count > 0) else "weak"
        steps.append(
            {
                "id": "gatt",
                "label": "GATT",
                "status": gatt_status,
                "detail": (
                    f"{service_count} svc · {characteristic_count} char · "
                    f"{int(active_validation.get('writable_count') or 0)} writable"
                    if active_attempted
                    else "not active-tested"
                ),
            }
        )

        intel_ok = bool(device.get("service_uuids")) or bool(device.get("vulnerability_matches")) or str(device.get("likely_family") or "generic_ble") != "generic_ble"
        steps.append(
            {
                "id": "intel",
                "label": "Intel",
                "status": "pass" if intel_ok else "weak",
                "detail": f"{len(device.get('service_uuids') or [])} uuid · {len(device.get('vulnerability_matches') or [])} vuln",
            }
        )

        validation_status = "validated"
        if any(step["status"] == "unknown" for step in steps):
            validation_status = "partial"
        if all(step["status"] == "weak" for step in steps if step["id"] != "pairable"):
            validation_status = "weak"

        highlights = [
            f"{auditability.get('state') or 'UNKNOWN'} auditability",
            f"{rf_quality.get('label') or 'WEAK'} RF",
            f"{device.get('vendor') or 'Unknown'} via {device.get('vendor_source') or 'unknown'}",
            f"{device.get('likely_family') or 'generic_ble'}",
            f"{str(device.get('pairable') or 'no').upper()} pairable",
            active_validation.get("detail") or "active test pending",
            f"{(device.get('risk') or {}).get('tier') or 'baseline'} {(device.get('risk') or {}).get('score') or 0}",
        ]
        if int(validation_suite.get("scenario_count") or 0) > 0:
            highlights.append(f"{validation_suite.get('scenario_count')} validation scenarios")
        return {
            "status": validation_status,
            "steps": steps,
            "highlights": highlights,
        }

    def _weakness_rank(self, device: Dict[str, Any]) -> int:
        risk = device.get("risk") if isinstance(device.get("risk"), dict) else {}
        validation = device.get("validation") if isinstance(device.get("validation"), dict) else {}
        validation_suite = device.get("validation_suite") if isinstance(device.get("validation_suite"), dict) else {}
        active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        score = int(risk.get("score") or 0)
        if str(risk.get("tier") or "") == "critical":
            score += 30
        elif str(risk.get("tier") or "") == "high":
            score += 20
        if str(device.get("pairable") or "").lower() == "yes":
            score += 18
        if str(validation.get("legacy_pin_risk") or "").lower() == "likely":
            score += 22
        if str(validation_suite.get("status") or "").lower() == "fail":
            score += 18
        elif str(validation_suite.get("status") or "").lower() == "weak":
            score += 10
        if int(device.get("writable_unauth_count") or 0) > 0:
            score += 24
        if int(device.get("sensitive_surface_count") or 0) > 0:
            score += 10
        if str(active_validation.get("connect_result") or "").lower() == "connected":
            score += 8
        if "reconnect_instability" in (device.get("anomaly_flags") or []):
            score += 6
        return score

    def _merge_clustered_devices(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        passthrough: list[dict[str, Any]] = []
        for device in devices:
            merge_key = self._cluster_merge_key(device)
            if not merge_key:
                passthrough.append(device)
                continue
            if merge_key not in grouped:
                grouped[merge_key] = device
                continue
            primary = grouped[merge_key]
            primary["observation_count"] += int(device.get("observation_count") or 0)
            primary["first_seen"] = min(float(primary.get("first_seen") or 0), float(device.get("first_seen") or 0))
            primary["last_seen"] = max(float(primary.get("last_seen") or 0), float(device.get("last_seen") or 0))
            if primary.get("name") == "Unknown BLE Device" and str(device.get("name") or "") != "Unknown BLE Device":
                primary["name"] = device.get("name")
            if primary.get("vendor") in {"", "Unknown"} and device.get("vendor"):
                primary["vendor"] = device.get("vendor")
            primary["connectable"] = bool(primary.get("connectable")) or bool(device.get("connectable"))
            primary["scannable"] = bool(primary.get("scannable")) or bool(device.get("scannable"))
            primary["service_uuids"] = sorted(set(primary.get("service_uuids") or []).union(device.get("service_uuids") or []))
            primary["priority_classes"] = sorted(set(primary.get("priority_classes") or []).union(device.get("priority_classes") or []))
            primary["sensor_ids"] = sorted(set(primary.get("sensor_ids") or []).union(device.get("sensor_ids") or []))
            primary["behavioral_tags"] = sorted(set(primary.get("behavioral_tags") or []).union(device.get("behavioral_tags") or []))
            primary["identity_variants"] = int(primary.get("identity_variants") or 1) + int(device.get("identity_variants") or 1)
            primary["service_signatures"] = max(int(primary.get("service_signatures") or 1), int(device.get("service_signatures") or 1))
            if primary.get("manufacturer_company_id") is None and device.get("manufacturer_company_id") is not None:
                primary["manufacturer_company_id"] = device.get("manufacturer_company_id")
            if not primary.get("manufacturer_data_hash") and device.get("manufacturer_data_hash"):
                primary["manufacturer_data_hash"] = device.get("manufacturer_data_hash")
            if not primary.get("manufacturer_data_prefix") and device.get("manufacturer_data_prefix"):
                primary["manufacturer_data_prefix"] = device.get("manufacturer_data_prefix")
            primary_linked = set(str(item).lower() for item in (primary.get("linked_addresses") or []) if str(item).strip())
            primary_linked.add(str(primary.get("address") or "").lower())
            primary_linked.update(str(item).lower() for item in (device.get("linked_addresses") or []) if str(item).strip())
            primary_linked.add(str(device.get("address") or "").lower())
            primary["linked_addresses"] = sorted(item for item in primary_linked if item)
            primary["linked_address_count"] = len(primary["linked_addresses"])
            if primary.get("identity_confidence") == "low" and device.get("identity_confidence") in {"medium", "high"}:
                primary["identity_confidence"] = device.get("identity_confidence")
            if primary.get("vendor_confidence") == "low" and device.get("vendor_confidence") in {"medium", "high"}:
                primary["vendor_confidence"] = device.get("vendor_confidence")
            if primary.get("category_confidence") == "low" and device.get("category_confidence") in {"medium", "high"}:
                primary["category_confidence"] = device.get("category_confidence")
        return passthrough + list(grouped.values())

    def _apply_preclassification_clusters(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not devices:
            return devices
        normalized_rows: list[dict[str, Any]] = []
        for device in devices:
            normalized = normalize_observation(
                {
                    "address": device.get("address"),
                    "address_type": device.get("address_type"),
                    "avg_rssi": device.get("avg_rssi"),
                    "connectable": device.get("connectable"),
                    "manufacturer_data_prefix": device.get("manufacturer_data_prefix"),
                    "service_uuids": device.get("service_uuids") or [],
                    "manufacturer_company_id": device.get("manufacturer_company_id"),
                    "name": device.get("name"),
                    "last_seen": device.get("last_seen"),
                    "observation_count": device.get("observation_count"),
                    "advertising_interval_ms": device.get("advertising_interval_ms"),
                }
            )
            normalized["device_key"] = str(device.get("device_key") or "")
            normalized_rows.append(normalized)
        clusters = cluster_devices(normalized_rows)
        cluster_counter = 0
        cluster_by_key: dict[str, dict[str, Any]] = {}
        for cluster in clusters:
            cluster_counter += 1
            classification = classify_cluster(cluster)
            confidence = compute_confidence(cluster)
            cluster_id = f"ble_cluster_{cluster_counter:03d}"
            addresses = sorted(str(item.get("mac") or "").lower() for item in cluster if str(item.get("mac") or "").strip())
            for item in cluster:
                cluster_by_key[str(item.get("device_key") or "")] = {
                    "cluster_id": cluster_id,
                    "cluster_size": len(cluster),
                    "cluster_classification": classification,
                    "cluster_confidence": confidence,
                    "cluster_addresses": addresses,
                }
        for device in devices:
            cluster_payload = cluster_by_key.get(str(device.get("device_key") or ""))
            if not cluster_payload:
                continue
            device["preclass_cluster_id"] = cluster_payload["cluster_id"]
            device["preclass_cluster_size"] = cluster_payload["cluster_size"]
            device["preclass_cluster_classification"] = cluster_payload["cluster_classification"]
            device["preclass_cluster_confidence"] = cluster_payload["cluster_confidence"]
            device["preclass_cluster_addresses"] = list(cluster_payload["cluster_addresses"])
        return devices

    def _identity_cluster_score(self, left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
        score = 0.0
        evidence: List[str] = []
        if str(left.get("device_key") or "") == str(right.get("device_key") or ""):
            return {"score": 1.0, "evidence": ["same_device_key"], "ambiguity": False}
        left_address = str(left.get("address") or "").lower()
        right_address = str(right.get("address") or "").lower()
        if left_address and right_address and left_address == right_address:
            return {"score": 1.0, "evidence": ["same_address"], "ambiguity": False}
        left_vendor = str(left.get("vendor") or "Unknown")
        right_vendor = str(right.get("vendor") or "Unknown")
        if left_vendor != "Unknown" and left_vendor == right_vendor:
            score += 0.12
            evidence.append("vendor_match")
        left_class = left.get("classification") if isinstance(left.get("classification"), dict) else {}
        right_class = right.get("classification") if isinstance(right.get("classification"), dict) else {}
        left_matched_device = str(left_class.get("matched_device") or "").strip()
        right_matched_device = str(right_class.get("matched_device") or "").strip()
        left_matched_confidence = int(left_class.get("confidence") or 0)
        right_matched_confidence = int(right_class.get("confidence") or 0)
        if (
            left_matched_device
            and left_matched_device == right_matched_device
            and left_matched_device not in {"IoT Candidate", "BLE Beacon"}
            and min(left_matched_confidence, right_matched_confidence) >= 70
        ):
            score += 0.18
            evidence.append("matched_device_cluster")
        try:
            left_company = left.get("manufacturer_company_id")
            right_company = right.get("manufacturer_company_id")
            if left_company is not None and right_company is not None and int(left_company) == int(right_company):
                score += 0.12
                evidence.append("company_id_match")
        except Exception:
            pass
        if str(left.get("manufacturer_data_prefix") or "") and str(left.get("manufacturer_data_prefix") or "") == str(right.get("manufacturer_data_prefix") or ""):
            score += 0.28
            evidence.append("manufacturer_prefix_match")
        left_sig = str(left.get("service_uuid_signature") or ",".join(left.get("service_uuids") or []))
        right_sig = str(right.get("service_uuid_signature") or ",".join(right.get("service_uuids") or []))
        if left_sig and right_sig and left_sig == right_sig:
            score += 0.18
            evidence.append("service_signature_match")
        else:
            left_services = set(left.get("service_uuids") or [])
            right_services = set(right.get("service_uuids") or [])
            overlap = len(left_services.intersection(right_services))
            if overlap:
                score += min(0.16, 0.06 * overlap)
                evidence.append(f"service_overlap:{overlap}")
        left_flags = left.get("advertising_flags")
        right_flags = right.get("advertising_flags")
        if left_flags is not None and right_flags is not None and left_flags == right_flags:
            score += 0.08
            evidence.append("flags_match")
        left_prefix = ":".join(left_address.split(":")[:3]) if left_address else ""
        right_prefix = ":".join(right_address.split(":")[:3]) if right_address else ""
        if left_prefix and right_prefix and left_prefix == right_prefix and str(left.get("address_type") or "") == "public" and str(right.get("address_type") or "") == "public":
            score += 0.1
            evidence.append("public_prefix_match")
        left_lengths = set(int(item) for item in (left.get("packet_lengths") or []) if int(item) > 0)
        right_lengths = set(int(item) for item in (right.get("packet_lengths") or []) if int(item) > 0)
        if left_lengths and right_lengths and left_lengths.intersection(right_lengths):
            score += 0.08
            evidence.append("packet_length_overlap")
        left_structures = int(left.get("avg_structure_count") or 0)
        right_structures = int(right.get("avg_structure_count") or 0)
        if left_structures and right_structures and abs(left_structures - right_structures) <= 1:
            score += 0.05
            evidence.append("structure_similarity")
        left_type = str(left.get("device_type") or "")
        right_type = str(right.get("device_type") or "")
        if left_type and left_type == right_type and left_type != "bluetooth device":
            score += 0.06
            evidence.append("device_type_match")
        left_category = str(left.get("priority_class") or "")
        right_category = str(right.get("priority_class") or "")
        if left_category and left_category == right_category and left_category != "general":
            score += 0.05
            evidence.append("category_match")
        left_interval = left.get("advertising_interval_ms")
        right_interval = right.get("advertising_interval_ms")
        if left_interval is not None and right_interval is not None:
            try:
                delta = abs(float(left_interval) - float(right_interval))
                if delta <= 150:
                    score += 0.1
                    evidence.append("cadence_match")
                elif delta <= 400:
                    score += 0.05
                    evidence.append("cadence_close")
            except Exception:
                pass
        left_rssi = left.get("avg_rssi")
        right_rssi = right.get("avg_rssi")
        if left_rssi is not None and right_rssi is not None:
            try:
                delta = abs(float(left_rssi) - float(right_rssi))
                if delta <= 6:
                    score += 0.08
                    evidence.append("rssi_close")
                elif delta <= 12:
                    score += 0.04
                    evidence.append("rssi_partial")
            except Exception:
                pass
        try:
            temporal_delta = abs(float(left.get("last_seen") or 0) - float(right.get("last_seen") or 0))
            if temporal_delta <= 4.0:
                score += 0.12
                evidence.append("temporal_burst_match")
            elif temporal_delta <= 12.0:
                score += 0.06
                evidence.append("temporal_proximity")
        except Exception:
            pass
        ambiguity = 0.42 <= score < 0.56
        return {"score": round(min(1.0, score), 3), "evidence": evidence, "ambiguity": ambiguity}

    def _cluster_logical_identities(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not devices:
            return devices
        parent = list(range(len(devices)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left: int, right: int) -> None:
            root_left = find(left)
            root_right = find(right)
            if root_left != root_right:
                parent[root_right] = root_left

        pair_evidence: Dict[tuple[int, int], Dict[str, Any]] = {}
        for left in range(len(devices)):
            for right in range(left + 1, len(devices)):
                score = self._identity_cluster_score(devices[left], devices[right])
                pair_evidence[(left, right)] = score
                if float(score.get("score") or 0.0) >= 0.56:
                    union(left, right)

        clusters: Dict[int, List[int]] = {}
        for index in range(len(devices)):
            clusters.setdefault(find(index), []).append(index)

        for _, indices in clusters.items():
            members = [devices[index] for index in indices]
            linked_addresses = sorted({str(member.get("address") or "").lower() for member in members if str(member.get("address") or "").strip()})
            logical_parts: set[str] = set()
            for member in members:
                logical_parts.update(
                    {
                        str(member.get("manufacturer_data_prefix") or ""),
                        str(member.get("service_uuid_signature") or ""),
                        str(member.get("vendor") or ""),
                        str(member.get("device_type") or ""),
                    }
                )
            logical_seed = "|".join(sorted(part for part in logical_parts if part))
            if len(linked_addresses) <= 1:
                logical_seed = "|".join(
                    [
                        logical_seed,
                        linked_addresses[0] if linked_addresses else "",
                    ]
                ).strip("|")
            logical_device_id = sha1(logical_seed.encode("utf-8")).hexdigest()[:16] if logical_seed else sha1(",".join(linked_addresses).encode("utf-8")).hexdigest()[:16]
            evidence_rows: List[Dict[str, Any]] = []
            cluster_scores: List[float] = []
            ambiguity = False
            for left in range(len(indices)):
                for right in range(left + 1, len(indices)):
                    item = pair_evidence.get((min(indices[left], indices[right]), max(indices[left], indices[right]))) or {}
                    if not item:
                        continue
                    score_value = float(item.get("score") or 0.0)
                    cluster_scores.append(score_value)
                    ambiguity = ambiguity or bool(item.get("ambiguity"))
                    evidence_rows.append(
                        {
                            "left_address": members[left].get("address"),
                            "right_address": members[right].get("address"),
                            "score": score_value,
                            "evidence": list(item.get("evidence") or []),
                        }
                    )
            confidence = round(max(cluster_scores) if cluster_scores else (1.0 if len(linked_addresses) <= 1 else 0.5), 3)
            for member in members:
                member["logical_device_id"] = logical_device_id
                member["linked_addresses"] = linked_addresses
                member["identity_cluster_confidence"] = confidence
                member["identity_cluster_evidence"] = evidence_rows[:8]
                member["identity_cluster_ambiguity"] = ambiguity
                member["linked_address_count"] = len(linked_addresses)
        return devices

    def _trust_lifecycle_analysis(self, device: Dict[str, Any]) -> Dict[str, Any]:
        validation_run = device.get("validation_run") if isinstance(device.get("validation_run"), dict) else {}
        trust = validation_run.get("trust_lifecycle") if isinstance(validation_run.get("trust_lifecycle"), dict) else {}
        pairing_transcript = validation_run.get("pairing_transcript") if isinstance(validation_run.get("pairing_transcript"), dict) else {}
        active = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        reconnect_probe = active.get("reconnect_probe") if isinstance(active.get("reconnect_probe"), dict) else {}
        timeline = list(pairing_transcript.get("steps") or [])
        if not timeline:
            timeline = [
                {"step": "observed", "status": "completed", "detail": "passive RF observation recorded"},
                {"step": "resolution", "status": str(device.get("resolution_state") or "observed"), "detail": str(device.get("resolution_summary") or "no host resolution evidence")},
            ]
            if active:
                timeline.append({"step": "active_test", "status": str(active.get("outcome") or "unknown"), "detail": str(active.get("detail") or "")})
        inconsistencies: List[str] = []
        if bool(trust.get("trusted_after")) and not bool(trust.get("paired_after")):
            inconsistencies.append("trusted_without_pair")
        if str(reconnect_probe.get("result") or "").lower() in {"reconnect_failed", "device_not_materialized"}:
            inconsistencies.append("reconnect_instability")
        if trust.get("trust_replacement_events") or trust.get("downgrade_indicators"):
            inconsistencies.append("trust_replacement_or_downgrade")
        return {
            "timeline": timeline,
            "pairing_method_classification": str(trust.get("pairing_method") or pairing_transcript.get("pairing_method") or "unknown"),
            "pairing_method_confidence": str(pairing_transcript.get("method_confidence") or "unknown"),
            "bond_lifecycle_events": {
                "bond_events": int(trust.get("bond_events") or device.get("bond_events") or 0),
                "trust_replacement_events": int(trust.get("trust_replacement_events") or 0),
                "downgrade_indicators": list(trust.get("downgrade_indicators") or []),
            },
            "reconnect_behavior_summary": str(trust.get("reconnect_result") or reconnect_probe.get("result") or "not_attempted"),
            "inconsistencies": inconsistencies,
            "summary": str(trust.get("summary") or active.get("operator_summary") or "trust lifecycle not validated"),
        }

    def _gatt_control_surface_analysis(self, device: Dict[str, Any]) -> Dict[str, Any]:
        active = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
        services = list(active.get("services") or [])
        control_surfaces: List[Dict[str, Any]] = []
        vendor_specific_count = 0
        maintenance_count = 0
        descriptor_count = int(active.get("descriptor_count") or 0)
        cccd_count = int(active.get("cccd_count") or 0)
        indicate_count = int(active.get("indicate_count") or 0)
        for service in services:
            service_uuid = str(service.get("uuid") or "").lower()
            is_vendor_specific = not service_uuid.startswith("000018") and service_uuid != ""
            if is_vendor_specific:
                vendor_specific_count += 1
            if any(token in service_uuid for token in ("fe59", "feaa", "1530", "dfu", "f000")):
                maintenance_count += 1
            for characteristic in service.get("characteristics") or []:
                flags = [str(item).lower() for item in (characteristic.get("flags") or [])]
                writable = bool(characteristic.get("writable"))
                readable = bool(characteristic.get("readable"))
                notifiable = bool(characteristic.get("notifiable"))
                requires_auth = bool(characteristic.get("requires_auth"))
                potential_control = writable or ("write-without-response" in flags)
                if potential_control:
                    control_surfaces.append(
                        {
                            "service_uuid": service_uuid,
                            "characteristic_uuid": str(characteristic.get("uuid") or "").lower(),
                            "flags": flags,
                            "requires_auth": requires_auth,
                            "vendor_specific": is_vendor_specific,
                            "control_surface": True,
                            "unauthenticated_writable": writable and not requires_auth,
                            "descriptor_count": len(characteristic.get("descriptors") or []),
                        }
                    )
                elif readable and notifiable and is_vendor_specific:
                    control_surfaces.append(
                        {
                            "service_uuid": service_uuid,
                            "characteristic_uuid": str(characteristic.get("uuid") or "").lower(),
                            "flags": flags,
                            "requires_auth": requires_auth,
                            "vendor_specific": True,
                            "control_surface": False,
                            "unauthenticated_writable": False,
                            "descriptor_count": len(characteristic.get("descriptors") or []),
                        }
                    )
        unauth_writable = int(active.get("unauth_writable_count") or 0)
        access_consistency = "consistent"
        if not services:
            access_consistency = "unresolved"
        elif unauth_writable > 0:
            access_consistency = "permissive"
        elif str(active.get("outcome") or "") == "partial":
            access_consistency = "partial"
        return {
            "total_services": int(active.get("service_count") or 0),
            "total_characteristics": int(active.get("characteristic_count") or 0),
            "access_breakdown": {
                "readable": int(active.get("readable_count") or 0),
                "writable": int(active.get("writable_count") or 0),
                "notify_or_indicate": int(active.get("notify_count") or 0),
                "unauth_readable": int(active.get("unauth_readable_count") or 0),
                "unauth_writable": unauth_writable,
            },
            "potential_control_surfaces": control_surfaces[:20],
            "vendor_specific_services": vendor_specific_count,
            "maintenance_endpoints": maintenance_count,
            "descriptor_count": descriptor_count,
            "cccd_count": cccd_count,
            "indicate_count": indicate_count,
            "access_consistency": access_consistency,
            "evidence_summary": str(active.get("detail") or "no active GATT evidence"),
        }

    def _build_gatt_engine_report(self, device: Dict[str, Any], active_validation: Dict[str, Any]) -> Dict[str, Any]:
        active = active_validation if isinstance(active_validation, dict) else {}
        services = list(active.get("services") or [])
        gatt_differential = active.get("gatt_differential") if isinstance(active.get("gatt_differential"), dict) else {}
        harder_test_results = list(active.get("harder_test_results") or [])
        gatt_analysis = self._gatt_control_surface_analysis({"active_validation": active})
        service_count = int(active.get("service_count") or 0)
        characteristic_count = int(active.get("characteristic_count") or 0)
        readable_count = int(active.get("readable_count") or 0)
        writable_count = int(active.get("writable_count") or 0)
        notify_count = int(active.get("notify_count") or 0)
        unauth_readable = int(active.get("unauth_readable_count") or 0)
        unauth_writable = int(active.get("unauth_writable_count") or 0)
        paired = bool((active.get("info") or {}).get("paired"))
        trusted = bool((active.get("info") or {}).get("trusted"))
        services_resolved = bool(active.get("services_resolved"))
        control_surfaces = list(gatt_analysis.get("potential_control_surfaces") or [])
        maintenance_endpoints = int(gatt_analysis.get("maintenance_endpoints") or 0)
        vendor_specific_services = int(gatt_analysis.get("vendor_specific_services") or 0)
        descriptor_count = int(active.get("descriptor_count") or 0)
        cccd_count = int(active.get("cccd_count") or 0)
        indicate_count = int(active.get("indicate_count") or 0)

        classifications: List[Dict[str, Any]] = []
        risk_findings: List[Dict[str, Any]] = []
        for service in services:
            service_uuid = str(service.get("uuid") or "").lower()
            for characteristic in service.get("characteristics") or []:
                flags = [str(item).lower() for item in (characteristic.get("flags") or [])]
                characteristic_uuid = str(characteristic.get("uuid") or "").lower()
                writable = bool(characteristic.get("writable"))
                readable = bool(characteristic.get("readable"))
                notifiable = bool(characteristic.get("notifiable"))
                requires_auth = bool(characteristic.get("requires_auth"))
                classification = "informational"
                if service_uuid in self.GATT_DFU_UUID_HINTS or characteristic_uuid in self.GATT_DFU_UUID_HINTS or any(token in characteristic_uuid for token in ("dfu", "f000ffc0", "f000ffc1")):
                    classification = "firmware_interface"
                elif writable and (not requires_auth):
                    classification = "control_surface"
                elif writable:
                    classification = "configuration"
                elif notifiable and readable:
                    classification = "telemetry_channel"
                classifications.append(
                    {
                        "service_uuid": service_uuid,
                        "characteristic_uuid": characteristic_uuid,
                        "classification": classification,
                        "flags": flags,
                        "requires_auth": requires_auth,
                    }
                )
                if classification == "control_surface" and not requires_auth:
                    risk_findings.append(
                        {
                            "category": "unauthenticated_writable_characteristic",
                            "severity": "high",
                            "evidence": f"{characteristic_uuid} writable without authenticated protection",
                        }
                    )
                if classification == "firmware_interface":
                    risk_findings.append(
                        {
                            "category": "exposed_firmware_interface",
                            "severity": "high" if not requires_auth else "medium",
                            "evidence": f"{characteristic_uuid or service_uuid} appears to expose firmware or maintenance behavior",
                        }
                    )
        if vendor_specific_services > 0:
            risk_findings.append(
                {
                    "category": "vendor_specific_gatt_surface",
                    "severity": "medium",
                    "evidence": f"{vendor_specific_services} vendor-specific service(s) exposed",
                }
            )
        if cccd_count > 0 and not paired:
            risk_findings.append(
                {
                    "category": "pre_association_notification_surface",
                    "severity": "medium",
                    "evidence": f"{cccd_count} client configuration descriptor(s) exposed before pairing",
                }
            )
        if unauth_readable > 0 and not paired:
            risk_findings.append(
                {
                    "category": "pre_association_read_surface",
                    "severity": "medium",
                    "evidence": f"{unauth_readable} readable characteristics exposed before pairing",
                }
            )
        for result in harder_test_results:
            if not isinstance(result, dict):
                continue
            if str(result.get("id") or "") == "notify_surface" and int(((result.get("metrics") or {}).get("successful_subscriptions")) or 0) > 0 and not paired:
                risk_findings.append(
                    {
                        "category": "pre_association_notify_subscription",
                        "severity": "medium",
                        "evidence": str(result.get("detail") or "notify subscription probe succeeded before pairing"),
                    }
                )

        differential_summary = []
        if str(gatt_differential.get("summary") or "").strip():
            differential_summary.append(str(gatt_differential.get("summary") or "").strip())
        if service_count > 0 and not paired:
            differential_summary.append("services visible before pairing")
        if unauth_writable > 0:
            differential_summary.append("writable paths exposed without authenticated trust")
        if services_resolved:
            differential_summary.append("services resolved by BlueZ session")
        if trusted and not paired:
            differential_summary.append("trusted state persisted without pairing completion")
        executed_harder = [item for item in harder_test_results if isinstance(item, dict) and bool(item.get("executed"))]
        if executed_harder:
            differential_summary.append(f"{len(executed_harder)} harder audit vector(s) executed")
        if not differential_summary:
            differential_summary.append("no strong state differential captured")

        stages = [
            {
                "id": "resolve",
                "label": "Resolve",
                "state": "completed" if str(device.get("resolution_state") or "") in {"materialized", "validation_ready"} else "blocked",
                "detail": str(device.get("resolution_summary") or "no host target"),
                "percent": 100 if str(device.get("resolution_state") or "") in {"materialized", "validation_ready"} else 28,
            },
            {
                "id": "map",
                "label": "Map",
                "state": "completed" if service_count > 0 or characteristic_count > 0 else "blocked",
                "detail": f"{service_count} svc · {characteristic_count} char · {descriptor_count} desc",
                "percent": 100 if service_count > 0 or characteristic_count > 0 else 32,
            },
            {
                "id": "diff",
                "label": "Diff",
                "state": "completed" if service_count > 0 else "weak",
                "detail": "; ".join(differential_summary[:2]),
                "percent": 88 if service_count > 0 else 40,
            },
            {
                "id": "control",
                "label": "Control",
                "state": "completed" if control_surfaces else ("weak" if vendor_specific_services else "idle"),
                "detail": f"{len(control_surfaces)} control · {vendor_specific_services} vendor · {maintenance_endpoints} firmware · {cccd_count} cccd",
                "percent": 100 if control_surfaces else (64 if vendor_specific_services else 24),
            },
            {
                "id": "transcript",
                "label": "Transcript",
                "state": "completed" if active.get("raw_output") or active.get("attribute_lines") else "weak",
                "detail": f"{len(active.get('attribute_lines') or [])} lines · {len(active.get('errors') or [])} errors",
                "percent": 96 if active.get("raw_output") or active.get("attribute_lines") else 42,
            },
            {
                "id": "classify",
                "label": "Classify",
                "state": "completed" if risk_findings else ("weak" if service_count > 0 else "idle"),
                "detail": f"{len(risk_findings)} findings · {gatt_analysis.get('access_consistency') or 'unknown'} access",
                "percent": 100 if risk_findings else (68 if service_count > 0 else 18),
            },
        ]

        if risk_findings:
            status = "high_value"
            summary = f"{len(risk_findings)} high-value GATT finding(s) across {service_count} service(s)"
        elif service_count > 0:
            status = "mapped"
            summary = f"GATT surface mapped: {service_count} service(s), {characteristic_count} characteristic(s)"
        else:
            status = "blocked"
            summary = "GATT surface unavailable on current session"

        return {
            "status": status,
            "tested_at": time.time(),
            "summary": summary,
            "stages": stages,
            "service_count": service_count,
            "characteristic_count": characteristic_count,
            "descriptor_count": descriptor_count,
            "access_breakdown": {
                "readable": readable_count,
                "writable": writable_count,
                "notify_or_indicate": notify_count,
                "indicate_only": indicate_count,
                "unauth_readable": unauth_readable,
                "unauth_writable": unauth_writable,
            },
            "state_profile": {
                "paired": paired,
                "trusted": trusted,
                "services_resolved": services_resolved,
                "connect_result": str(active.get("connect_result") or "unknown"),
            },
            "access_consistency": gatt_analysis.get("access_consistency") or "unknown",
            "vendor_specific_services": vendor_specific_services,
            "maintenance_endpoints": maintenance_endpoints,
            "cccd_count": cccd_count,
            "control_surfaces": control_surfaces[:20],
            "classifications": classifications[:40],
            "risk_findings": risk_findings,
            "recommended_actions": [
                "Compare unauthenticated vs trusted-session access to writable characteristics.",
                "Re-run GATT test after a reconnect and compare control-surface drift.",
                "Review vendor-specific writable paths, notification descriptors, and firmware interfaces for authorization controls.",
            ],
            "gatt_differential": gatt_differential,
            "harder_test_results": harder_test_results,
            "transcript": {
                "attribute_lines": list(active.get("attribute_lines") or []),
                "raw_output": str(active.get("raw_output") or "")[-4000:],
                "errors": list(active.get("errors") or []),
            },
        }

    def _persist_gatt_test(self, device_key: str, gatt_test: Dict[str, Any], notes: str = "") -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        tasks = self._task_state_map()
        existing = tasks.get(normalized_key) or self._workflow_descriptor("validate")
        tasks[normalized_key] = {
            "device_key": normalized_key,
            "workflow": existing.get("workflow") or "validate",
            "state": "gatt_tested",
            "label": existing.get("label") or "Validate",
            "summary": "Dedicated GATT control-surface audit executed.",
            "notes": str(notes or existing.get("notes") or "").strip(),
            "source": existing.get("source") or "manual",
            "updated_at": time.time(),
            "validation": existing.get("validation") if isinstance(existing.get("validation"), dict) else {},
            "active_validation": existing.get("active_validation") if isinstance(existing.get("active_validation"), dict) else {},
            "validation_suite": existing.get("validation_suite") if isinstance(existing.get("validation_suite"), dict) else {},
            "validation_run": existing.get("validation_run") if isinstance(existing.get("validation_run"), dict) else {},
            "gatt_test": gatt_test,
            "validation_history": list(existing.get("validation_history") or []),
        }
        self._save_task_state_map(tasks)
        return tasks[normalized_key]

    def run_gatt_test(self, device_key: str, notes: str = "", owned_target: bool = False) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"status": "error", "error": "device_key is required"}
        if not owned_target:
            return {"status": "error", "error": "owned_target confirmation is required"}
        if not self.lab_mode:
            return {"status": "error", "error": "lab mode is required"}
        claim = self._claim_device_operation(normalized_key, "gatt_test")
        if not claim.get("ok"):
            return {"status": "error", "error": claim.get("error"), "detail": claim.get("detail")}
        device = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None)
        try:
            if device is None:
                return {"status": "error", "error": "device not found"}
            gate = self._auditability_gate(device)
            if gate["state"] != "AUDITABLE":
                blocked_active = self._blocked_validation_result(
                    device,
                    tested_at=time.time(),
                    connect_result="blocked_auditability_gate",
                    detail=gate["reason"],
                    next_best_action=gate["action"],
                    error_code="auditability_gate_blocked",
                )
                self._persist_active_validation(normalized_key, blocked_active, notes=notes)
                return {
                    "status": "blocked",
                    "error": "auditability_gate_blocked",
                    "detail": gate["reason"],
                    "active_validation": blocked_active,
                }

            self.gatt_engine_state = {
                "status": "running",
                "device_key": normalized_key,
                "device_name": str(device.get("name") or "Unknown BLE Device"),
                "summary": "Running dedicated GATT control-surface audit",
                "stages": [
                    {"id": "resolve", "label": "Resolve", "state": "active", "detail": "materializing host target", "percent": 18},
                    {"id": "map", "label": "Map", "state": "idle", "detail": "awaiting service map", "percent": 0},
                    {"id": "diff", "label": "Diff", "state": "idle", "detail": "awaiting access comparison", "percent": 0},
                    {"id": "control", "label": "Control", "state": "idle", "detail": "awaiting control-surface classification", "percent": 0},
                    {"id": "transcript", "label": "Transcript", "state": "idle", "detail": "awaiting GATT transcript", "percent": 0},
                    {"id": "classify", "label": "Classify", "state": "idle", "detail": "awaiting risk classification", "percent": 0},
                ],
                "updated_at": time.time(),
            }

            session_owner = f"gatt_test:{threading.get_ident()}:{time.time():.6f}"
            active_validation = self._run_active_validation(device, session_owner=session_owner)
            self._persist_active_validation(normalized_key, active_validation, notes=notes)
            refreshed = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None) or device
            gatt_test = self._build_gatt_engine_report(refreshed, active_validation)
            task = self._persist_gatt_test(normalized_key, gatt_test, notes=notes)
            self.gatt_engine_state = {
                "status": gatt_test.get("status") or "idle",
                "device_key": normalized_key,
                "device_name": str(refreshed.get("name") or "Unknown BLE Device"),
                "summary": str(gatt_test.get("summary") or "GATT engine idle"),
                "stages": list(gatt_test.get("stages") or []),
                "updated_at": time.time(),
            }
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": time.time(),
                    "event_type": "gatt_test",
                    "device_key": normalized_key,
                    "status": gatt_test.get("status"),
                    "service_count": gatt_test.get("service_count"),
                    "characteristic_count": gatt_test.get("characteristic_count"),
                },
            )
            return {
                "status": "completed",
                "gatt_test": gatt_test,
                "active_validation": active_validation,
                "task": task,
            }
        finally:
            self._release_device_operation(normalized_key, "gatt_test")

    def run_hard_ble_test(self, device_key: str, notes: str = "", owned_target: bool = False) -> Dict[str, Any]:
        normalized_key = str(device_key or "").strip().lower()
        if not normalized_key:
            return {"status": "error", "error": "device_key is required"}
        if not owned_target:
            return {"status": "error", "error": "owned_target confirmation is required"}
        if not self.lab_mode:
            self.lab_mode = True
            self.last_profile = "red_team_validation"
            self.last_mission = "gatt_analysis"
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": time.time(),
                    "event_type": "session_reprofile",
                    "profile": self.last_profile,
                    "mission": self.last_mission,
                    "lab_mode": self.lab_mode,
                    "detail": "Hard BLE test promoted controller into lab mode automatically.",
                },
            )
        claim = self._claim_device_operation(normalized_key, "hard_ble_test")
        if not claim.get("ok"):
            return {"status": "error", "error": claim.get("error"), "detail": claim.get("detail")}
        device = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None)
        if device is None:
            self._release_device_operation(normalized_key, "hard_ble_test")
            return {"status": "error", "error": "device not found"}
        gate = self._auditability_gate(device)
        if gate["state"] != "AUDITABLE":
            blocked_active = self._blocked_validation_result(
                device,
                tested_at=time.time(),
                connect_result="blocked_auditability_gate",
                detail=gate["reason"],
                next_best_action=gate["action"],
                error_code="auditability_gate_blocked",
            )
            self._persist_active_validation(normalized_key, blocked_active, notes=notes)
            self._release_device_operation(normalized_key, "hard_ble_test")
            return {
                "status": "blocked",
                "error": "auditability_gate_blocked",
                "detail": gate["reason"],
                "active_validation": blocked_active,
            }
        started_at = time.time()
        try:
            self.hard_test_state = {
                "status": "running",
                "device_key": normalized_key,
                "device_name": str(device.get("name") or "Unknown BLE Device"),
                "summary": "Hard BLE test bootstrapped",
                "stages": [
                    {"id": "bootstrap", "label": "Bootstrap", "state": "active", "detail": "lab mode enabled", "percent": 22},
                    {"id": "active", "label": "Active", "state": "idle", "detail": "awaiting live trust probe", "percent": 0},
                    {"id": "suite", "label": "Suite", "state": "idle", "detail": "awaiting scenario workflow", "percent": 0},
                    {"id": "gatt", "label": "GATT", "state": "idle", "detail": "awaiting control-surface map", "percent": 0},
                    {"id": "finalize", "label": "Finalize", "state": "idle", "detail": "awaiting evidence merge", "percent": 0},
                ],
                "updated_at": time.time(),
            }
            self.identity_engine_state = {
                "status": "running",
                "summary": f"Hard BLE test running against {device.get('name') or 'selected target'}",
                "stages": [
                    {"id": "features", "label": "Features", "state": "completed", "detail": "target observation retained", "percent": 100},
                    {"id": "correlate", "label": "Correlate", "state": "active", "detail": "building identity/session context", "percent": 42},
                    {"id": "host", "label": "Host Bind", "state": "idle", "detail": "awaiting BlueZ materialization", "percent": 0},
                    {"id": "sessions", "label": "Sessions", "state": "idle", "detail": "awaiting validation binding", "percent": 0},
                    {"id": "state", "label": "State", "state": "idle", "detail": "awaiting trust and GATT snapshots", "percent": 0},
                ],
                "node_count": int((self._identity_graph_payload().get("summary") or {}).get("node_count") or 0),
                "resolved_hosts": int((self._identity_graph_payload().get("summary") or {}).get("resolved_hosts") or 0),
                "correlated_nodes": int((self._identity_graph_payload().get("summary") or {}).get("correlated_nodes") or 0),
                "updated_at": time.time(),
            }
            self.gatt_engine_state = {
                "status": "running",
                "device_key": normalized_key,
                "device_name": str(device.get("name") or "Unknown BLE Device"),
                "summary": "Hard BLE test running end-to-end validation",
                "stages": [
                    {"id": "resolve", "label": "Resolve", "state": "active", "detail": "materializing host target", "percent": 18},
                    {"id": "map", "label": "Map", "state": "idle", "detail": "awaiting service map", "percent": 0},
                    {"id": "diff", "label": "Diff", "state": "idle", "detail": "awaiting state comparison", "percent": 0},
                    {"id": "control", "label": "Control", "state": "idle", "detail": "awaiting control audit", "percent": 0},
                    {"id": "transcript", "label": "Transcript", "state": "idle", "detail": "awaiting att transcript", "percent": 0},
                    {"id": "classify", "label": "Classify", "state": "idle", "detail": "awaiting risk findings", "percent": 0},
                ],
                "updated_at": time.time(),
            }

            session_owner = f"hard_ble_test:{threading.get_ident()}:{time.time():.6f}"
            self.hard_test_state["stages"] = [
                {"id": "bootstrap", "label": "Bootstrap", "state": "completed", "detail": "lab mode ready", "percent": 100},
                {"id": "active", "label": "Active", "state": "active", "detail": "running host trust probe", "percent": 44},
                {"id": "suite", "label": "Suite", "state": "idle", "detail": "awaiting scenario workflow", "percent": 0},
                {"id": "gatt", "label": "GATT", "state": "idle", "detail": "awaiting control-surface map", "percent": 0},
                {"id": "finalize", "label": "Finalize", "state": "idle", "detail": "awaiting evidence merge", "percent": 0},
            ]
            self.hard_test_state["summary"] = "Active trust probe running"
            self.hard_test_state["updated_at"] = time.time()
            active_validation = self._run_active_validation(device, session_owner=session_owner)
            self._persist_active_validation(normalized_key, active_validation, notes=notes)

            self.identity_engine_state["stages"] = [
                {"id": "features", "label": "Features", "state": "completed", "detail": "target observation retained", "percent": 100},
                {"id": "correlate", "label": "Correlate", "state": "completed", "detail": f"{device.get('logical_device_id') or normalized_key} correlated", "percent": 100},
                {"id": "host", "label": "Host Bind", "state": "completed" if str((active_validation.get("resolution") or {}).get("state") or "").upper() in {"MATERIALIZED", "VALIDATION_READY"} else "weak", "detail": str(((active_validation.get("resolution") or {}).get("detail")) or "host resolution incomplete"), "percent": 100 if str((active_validation.get("resolution") or {}).get("state") or "").upper() in {"MATERIALIZED", "VALIDATION_READY"} else 54},
                {"id": "sessions", "label": "Sessions", "state": "active", "detail": "running validation suite", "percent": 72},
                {"id": "state", "label": "State", "state": "active", "detail": "capturing trust and GATT state", "percent": 68},
            ]
            self.identity_engine_state["updated_at"] = time.time()
            self.hard_test_state["stages"] = [
                {"id": "bootstrap", "label": "Bootstrap", "state": "completed", "detail": "lab mode ready", "percent": 100},
                {"id": "active", "label": "Active", "state": "completed" if str(active_validation.get("outcome") or "") not in {"failed", "blocked"} else ("blocked" if str(active_validation.get("outcome") or "") == "blocked" else "weak"), "detail": str(active_validation.get("detail") or "active probe complete"), "percent": 100 if str(active_validation.get("outcome") or "") not in {"failed", "blocked"} else 54},
                {"id": "suite", "label": "Suite", "state": "active", "detail": "running adversary scenarios", "percent": 72},
                {"id": "gatt", "label": "GATT", "state": "idle", "detail": "awaiting control-surface map", "percent": 0},
                {"id": "finalize", "label": "Finalize", "state": "idle", "detail": "awaiting evidence merge", "percent": 0},
            ]
            self.hard_test_state["summary"] = "Validation suite running"
            self.hard_test_state["updated_at"] = time.time()

            validation_run = self.validation_engine.execute_workflow(device, owned_target=True, notes=notes)
            if validation_run.get("status") == "error":
                self.hard_test_state = {
                    "status": "error",
                    "device_key": normalized_key,
                    "device_name": str(device.get("name") or "Unknown BLE Device"),
                    "summary": str(validation_run.get("error") or "Hard BLE test failed"),
                    "stages": [
                        {"id": "bootstrap", "label": "Bootstrap", "state": "completed", "detail": "lab mode ready", "percent": 100},
                        {"id": "active", "label": "Active", "state": "completed", "detail": str(active_validation.get("detail") or "active probe complete"), "percent": 100},
                        {"id": "suite", "label": "Suite", "state": "failed", "detail": str(validation_run.get("error") or "validation suite failed"), "percent": 48},
                        {"id": "gatt", "label": "GATT", "state": "idle", "detail": "not executed", "percent": 0},
                        {"id": "finalize", "label": "Finalize", "state": "idle", "detail": "not executed", "percent": 0},
                    ],
                    "updated_at": time.time(),
                }
                return validation_run

            refreshed = next((item for item in self._aggregate_devices() if str(item.get("device_key") or "").lower() == normalized_key), None) or device
            suite = self._suite_from_validation_run(validation_run)
            if str(active_validation.get("outcome") or "") == "blocked":
                suite["status"] = "blocked"
            elif str(active_validation.get("outcome") or "") == "failed":
                suite["status"] = "failed"
            elif str(active_validation.get("outcome") or "") == "partial" and suite.get("status") == "verified":
                suite["status"] = "partial"

            derived_validation = self._derive_validation_from_suite(refreshed, active_validation, validation_run, notes=notes)
            self.hard_test_state["stages"] = [
                {"id": "bootstrap", "label": "Bootstrap", "state": "completed", "detail": "lab mode ready", "percent": 100},
                {"id": "active", "label": "Active", "state": "completed" if str(active_validation.get("outcome") or "") not in {"failed", "blocked"} else ("blocked" if str(active_validation.get("outcome") or "") == "blocked" else "weak"), "detail": str(active_validation.get("detail") or "active probe complete"), "percent": 100 if str(active_validation.get("outcome") or "") not in {"failed", "blocked"} else 54},
                {"id": "suite", "label": "Suite", "state": "completed" if suite.get("status") in {"verified", "partial"} else ("blocked" if suite.get("status") == "blocked" else "weak"), "detail": f"{suite.get('scenario_count') or 0} scenarios · {suite.get('status') or 'unknown'}", "percent": 100 if suite.get("status") in {"verified", "partial"} else 64},
                {"id": "gatt", "label": "GATT", "state": "active", "detail": "building control-surface findings", "percent": 84},
                {"id": "finalize", "label": "Finalize", "state": "idle", "detail": "awaiting evidence merge", "percent": 0},
            ]
            self.hard_test_state["summary"] = "GATT engine running"
            self.hard_test_state["updated_at"] = time.time()
            gatt_test = self._build_gatt_engine_report(refreshed, active_validation)
            task = self._persist_gatt_test(normalized_key, gatt_test, notes=notes)
            tasks = self._task_state_map()
            existing = tasks.get(normalized_key) or task or self._workflow_descriptor("validate")
            history = list(existing.get("validation_history") or [])
            history.insert(
                0,
                {
                    "run_id": validation_run.get("run_id"),
                    "timestamp": validation_run.get("timestamp"),
                    "status": suite.get("status"),
                    "scenario_count": suite.get("scenario_count"),
                },
            )
            tasks[normalized_key] = {
                "device_key": normalized_key,
                "workflow": existing.get("workflow") or "validate",
                "state": "hard_tested",
                "label": existing.get("label") or "Validate",
                "summary": "Hard BLE test executed active, suite, and GATT workflows.",
                "notes": str(notes or existing.get("notes") or "").strip(),
                "source": existing.get("source") or "manual",
                "updated_at": time.time(),
                "validation": derived_validation,
                "active_validation": active_validation,
                "validation_suite": suite,
                "validation_run": validation_run,
                "pairing_transcript": validation_run.get("pairing_transcript") if isinstance(validation_run.get("pairing_transcript"), dict) else {},
                "validation_confidence": validation_run.get("validation_confidence") if isinstance(validation_run.get("validation_confidence"), dict) else {},
                "capture_plan": validation_run.get("capture_plan") if isinstance(validation_run.get("capture_plan"), dict) else {},
                "gatt_test": gatt_test,
                "validation_history": history[:10],
            }
            self._save_task_state_map(tasks)
            self._identity_graph_cache = None
            identity_graph = self._build_identity_graph(self._aggregate_devices())
            identity_summary = identity_graph.get("summary") if isinstance(identity_graph, dict) else {}
            self.identity_engine_state = {
                "status": "completed",
                "summary": f"Hard BLE test completed in {round(time.time() - started_at, 1)}s",
                "stages": [
                    {"id": "features", "label": "Features", "state": "completed", "detail": "target observation retained", "percent": 100},
                    {"id": "correlate", "label": "Correlate", "state": "completed", "detail": f"{int(identity_summary.get('correlated_nodes') or 0)} correlated identity node(s)", "percent": 100},
                    {"id": "host", "label": "Host Bind", "state": "completed" if str((active_validation.get("resolution") or {}).get("state") or "").upper() in {"MATERIALIZED", "VALIDATION_READY"} else "weak", "detail": str(((active_validation.get("resolution") or {}).get("detail")) or "host resolution incomplete"), "percent": 100 if str((active_validation.get("resolution") or {}).get("state") or "").upper() in {"MATERIALIZED", "VALIDATION_READY"} else 58},
                    {"id": "sessions", "label": "Sessions", "state": "completed", "detail": f"{suite.get('scenario_count') or 0} validation scenarios", "percent": 100},
                    {"id": "state", "label": "State", "state": "completed" if gatt_test.get("service_count") or gatt_test.get("characteristic_count") else "weak", "detail": f"{gatt_test.get('service_count') or 0} svc · {gatt_test.get('characteristic_count') or 0} char", "percent": 100 if gatt_test.get("service_count") or gatt_test.get("characteristic_count") else 48},
                ],
                "node_count": int(identity_summary.get("node_count") or 0),
                "resolved_hosts": int(identity_summary.get("resolved_hosts") or 0),
                "correlated_nodes": int(identity_summary.get("correlated_nodes") or 0),
                "updated_at": time.time(),
            }
            self.gatt_engine_state = {
                "status": gatt_test.get("status") or "idle",
                "device_key": normalized_key,
                "device_name": str(refreshed.get("name") or "Unknown BLE Device"),
                "summary": f"Hard BLE test · {gatt_test.get('summary') or 'GATT engine complete'}",
                "stages": list(gatt_test.get("stages") or []),
                "updated_at": time.time(),
            }
            self.hard_test_state = {
                "status": "completed",
                "device_key": normalized_key,
                "device_name": str(refreshed.get("name") or "Unknown BLE Device"),
                "summary": f"Hard BLE test complete · {suite.get('status') or 'unknown'} · {gatt_test.get('status') or 'idle'}",
                "stages": [
                    {"id": "bootstrap", "label": "Bootstrap", "state": "completed", "detail": "lab mode ready", "percent": 100},
                    {"id": "active", "label": "Active", "state": "completed" if str(active_validation.get("outcome") or "") not in {"failed", "blocked"} else ("blocked" if str(active_validation.get("outcome") or "") == "blocked" else "weak"), "detail": str(active_validation.get("detail") or "active probe complete"), "percent": 100 if str(active_validation.get("outcome") or "") not in {"failed", "blocked"} else 54},
                    {"id": "suite", "label": "Suite", "state": "completed" if suite.get("status") in {"verified", "partial"} else ("blocked" if suite.get("status") == "blocked" else "weak"), "detail": f"{suite.get('scenario_count') or 0} scenarios · {suite.get('status') or 'unknown'}", "percent": 100 if suite.get("status") in {"verified", "partial"} else 64},
                    {"id": "gatt", "label": "GATT", "state": "completed" if gatt_test.get("status") in {"mapped", "high_value"} else ("blocked" if gatt_test.get("status") == "blocked" else "weak"), "detail": str(gatt_test.get("summary") or "GATT complete"), "percent": 100 if gatt_test.get("status") in {"mapped", "high_value"} else 58},
                    {"id": "finalize", "label": "Finalize", "state": "completed", "detail": f"evidence merged in {round(time.time() - started_at, 1)}s", "percent": 100},
                ],
                "updated_at": time.time(),
            }
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": time.time(),
                    "event_type": "hard_ble_test",
                    "device_key": normalized_key,
                    "suite_status": suite.get("status"),
                    "gatt_status": gatt_test.get("status"),
                    "service_count": gatt_test.get("service_count"),
                    "characteristic_count": gatt_test.get("characteristic_count"),
                },
            )
            return {
                "status": "completed",
                "active_validation": active_validation,
                "validation_suite": suite,
                "validation_run": validation_run,
                "gatt_test": gatt_test,
                "task": tasks[normalized_key],
            }
        finally:
            self._release_device_operation(normalized_key, "hard_ble_test")

    def _aggregate_devices(self) -> list[dict[str, Any]]:
        events = self._read_jsonl(self.observation_log)
        grouped: dict[str, dict[str, Any]] = {}
        for event in events:
            key = self._normalize_device_key(event)
            device = grouped.setdefault(
                key,
                {
                    "device_key": key,
                    "address": event.get("address"),
                    "address_type": event.get("address_type") or "unknown",
                    "name": event.get("name") or "Unknown BLE Device",
                    "vendor": event.get("vendor") or event.get("manufacturer") or "Unknown",
                    "manufacturer_data_hash": event.get("manufacturer_data_hash") or "",
                    "manufacturer_company_id": event.get("manufacturer_company_id"),
                    "identity_confidence": event.get("identity_confidence") or "low",
                    "identity_reason": event.get("identity_reason") or "rotating_address_only",
                    "vendor_confidence": event.get("vendor_confidence") or "low",
                    "service_uuids": set(),
                    "appearance_class": event.get("appearance_class") or event.get("appearance") or "",
                    "device_type": event.get("device_type") or "bluetooth device",
                    "category_confidence": event.get("category_confidence") or "low",
                    "connectable": False,
                    "scannable": False,
                    "first_seen": event.get("timestamp") or time.time(),
                    "last_seen": event.get("timestamp") or time.time(),
                    "observation_count": 0,
                    "rssi_values": [],
                    "pairing_methods": set(),
                    "bond_events": 0,
                    "repair_flags": 0,
                    "pairing_failures": 0,
                    "silent_pairing_patterns": 0,
                    "gatt_readable_count": 0,
                    "gatt_writable_count": 0,
                    "writable_unauth_count": 0,
                    "sensitive_surface_count": 0,
                    "priority_class": event.get("priority_class") or "general",
                    "priority_classes": set(),
                    "sensor_ids": set(),
                    "behavioral_tags": set(),
                    "vulnerability_matches": [],
                    "verdict": event.get("verdict") or "Observed",
                    "manufacturer_data_prefix": event.get("manufacturer_data_prefix") or "",
                    "service_uuid_signature": event.get("service_uuid_signature") or "",
                    "identity_variants": 1,
                    "service_signatures_seen": set(),
                    "name_variants_seen": set(),
                    "packet_lengths_seen": set(),
                    "advertising_flags_seen": set(),
                    "structure_counts_seen": [],
                    "tx_power_values": [],
                    "channels_seen": set(),
                    "packet_types_seen": set(),
                    "service_data_uuids": set(),
                    "scan_response_seen": False,
                    "event_count": 0,
                    "seen_timestamps": [],
                },
            )
            timestamp = float(event.get("timestamp") or time.time())
            device["first_seen"] = min(float(device["first_seen"]), timestamp)
            device["last_seen"] = max(float(device["last_seen"]), timestamp)
            device["event_count"] += 1
            device["observation_count"] += max(1, int(event.get("observation_count") or event.get("frame_count") or 1))
            device["connectable"] = device["connectable"] or bool(event.get("connectable"))
            device["scannable"] = device["scannable"] or bool(event.get("scannable"))
            device["service_uuids"].update(str(item) for item in (event.get("service_uuids") or []))
            device["service_data_uuids"].update(str(item) for item in (event.get("service_data_uuids") or []))
            if device["name"] in {"", "Unknown BLE Device"} and event.get("name") and str(event.get("name")) != "Unknown BLE Device":
                device["name"] = str(event.get("name"))
            if device["vendor"] in {"", "Unknown"} and event.get("vendor"):
                device["vendor"] = str(event.get("vendor"))
            if event.get("device_type") and device.get("device_type") == "bluetooth device":
                device["device_type"] = str(event.get("device_type"))
            if event.get("identity_confidence") in {"high", "medium"}:
                device["identity_confidence"] = str(event.get("identity_confidence"))
            if event.get("identity_reason") and device.get("identity_reason") == "rotating_address_only":
                device["identity_reason"] = str(event.get("identity_reason"))
            if event.get("vendor_confidence") in {"high", "medium"}:
                device["vendor_confidence"] = str(event.get("vendor_confidence"))
            if event.get("category_confidence") in {"high", "medium"}:
                device["category_confidence"] = str(event.get("category_confidence"))
            if event.get("pairing_method"):
                device["pairing_methods"].add(str(event.get("pairing_method")))
            if event.get("bond_created") or event.get("bond_updated"):
                device["bond_events"] += 1
            if event.get("repair_flag"):
                device["repair_flags"] += 1
            if event.get("pairing_failure"):
                device["pairing_failures"] += 1
            if event.get("silent_pairing_pattern"):
                device["silent_pairing_patterns"] += 1
            device["gatt_readable_count"] += int(event.get("gatt_readable_count") or 0)
            device["gatt_writable_count"] += int(event.get("gatt_writable_count") or 0)
            device["writable_unauth_count"] += int(event.get("writable_unauth_count") or 0)
            device["sensitive_surface_count"] += int(event.get("sensitive_surface_count") or 0)
            if event.get("priority_class"):
                device["priority_class"] = str(event.get("priority_class"))
                device["priority_classes"].add(str(event.get("priority_class")))
            if event.get("sensor_id"):
                device["sensor_ids"].add(str(event.get("sensor_id")))
            if event.get("behavioral_tags"):
                device["behavioral_tags"].update(str(item) for item in (event.get("behavioral_tags") or []))
            if event.get("manufacturer_data_prefix") and not device.get("manufacturer_data_prefix"):
                device["manufacturer_data_prefix"] = str(event.get("manufacturer_data_prefix"))
            if event.get("service_uuid_signature") and not device.get("service_uuid_signature"):
                device["service_uuid_signature"] = str(event.get("service_uuid_signature"))
            device["scan_response_seen"] = bool(device.get("scan_response_seen")) or bool(event.get("scan_response_seen"))
            service_sig = ",".join(sorted(str(item).lower() for item in (event.get("service_uuids") or [])))
            if service_sig:
                device["service_signatures_seen"].add(service_sig)
            if event.get("name"):
                clean_name = str(event.get("name"))
                if clean_name:
                    device["name_variants_seen"].add(clean_name)
            packet_length = int(event.get("packet_length") or 0)
            if packet_length > 0:
                device["packet_lengths_seen"].add(packet_length)
            adv_flags = event.get("adv_flags")
            if adv_flags is not None:
                try:
                    device["advertising_flags_seen"].add(int(adv_flags))
                except Exception:
                    pass
            device["channels_seen"].update(int(item) for item in ([event.get("channel")] + list(event.get("channel_set") or [])) if item is not None)
            device["packet_types_seen"].update(str(item) for item in ([event.get("packet_type")] + list(event.get("packet_types") or [])) if str(item or "").strip())
            structure_count = int(event.get("ad_structure_count") or 0)
            if structure_count > 0:
                device["structure_counts_seen"].append(structure_count)
            tx_power = event.get("tx_power")
            if tx_power is not None:
                try:
                    device["tx_power_values"].append(float(tx_power))
                except Exception:
                    pass
            device["seen_timestamps"].append(timestamp)
            rssi = event.get("rssi")
            if rssi is not None:
                try:
                    device["rssi_values"].append(float(rssi))
                except Exception:
                    pass

        devices: list[dict[str, Any]] = []
        for device in grouped.values():
            device["service_uuids"] = sorted(device["service_uuids"])
            device["pairing_methods"] = sorted(device["pairing_methods"])
            device["priority_classes"] = sorted(device["priority_classes"])
            device["sensor_ids"] = sorted(device["sensor_ids"])
            device["behavioral_tags"] = sorted(device["behavioral_tags"])
            device["service_data_uuids"] = sorted(device["service_data_uuids"])
            device["channels_seen"] = sorted(int(item) for item in (device.get("channels_seen") or set()) if item is not None)
            device["packet_types_seen"] = sorted(str(item) for item in (device.get("packet_types_seen") or set()) if str(item).strip())
            if device["rssi_values"]:
                avg_rssi = sum(device["rssi_values"]) / len(device["rssi_values"])
            else:
                avg_rssi = None
            device["avg_rssi"] = round(avg_rssi, 1) if avg_rssi is not None else None
            if device["tx_power_values"]:
                avg_tx_power = sum(device["tx_power_values"]) / len(device["tx_power_values"])
            else:
                avg_tx_power = None
            device["avg_tx_power"] = round(avg_tx_power, 1) if avg_tx_power is not None else None
            seen_timestamps = sorted(float(item) for item in (device.pop("seen_timestamps", []) or []))
            intervals_ms: List[float] = []
            if len(seen_timestamps) > 1:
                intervals_ms = [max(0.0, (seen_timestamps[index] - seen_timestamps[index - 1]) * 1000.0) for index in range(1, len(seen_timestamps))]
            device["advertising_interval_ms"] = round(sum(intervals_ms) / len(intervals_ms), 1) if intervals_ms else None
            device["advertising_interval_samples"] = [round(value, 1) for value in intervals_ms[:12]]
            device["dwell_seconds"] = round(max(0.0, float(device["last_seen"]) - float(device["first_seen"])), 2)
            device["service_signatures"] = max(1, len(device.pop("service_signatures_seen", set()) or []))
            device["identity_variants"] = max(int(device.get("identity_variants") or 1), len(device.pop("name_variants_seen", set()) or []) or 1)
            packet_lengths_seen = sorted(int(item) for item in (device.pop("packet_lengths_seen", set()) or []) if int(item) > 0)
            advertising_flags_seen = sorted(int(item) for item in (device.pop("advertising_flags_seen", set()) or []))
            structure_counts_seen = [int(item) for item in (device.pop("structure_counts_seen", []) or []) if int(item) > 0]
            device.pop("tx_power_values", None)
            device["packet_lengths"] = packet_lengths_seen
            device["advertising_flags"] = advertising_flags_seen[0] if advertising_flags_seen else None
            device["advertising_flag_set"] = advertising_flags_seen
            device["avg_structure_count"] = round(sum(structure_counts_seen) / len(structure_counts_seen), 2) if structure_counts_seen else 0
            device["vulnerability_matches"] = self._risk_matches(device)
            device["risk"] = self._score_device(device)
            devices.append(device)

        devices = self._merge_clustered_devices(devices)
        devices = self._apply_preclassification_clusters(devices)
        for device in devices:
            self._reconcile_merged_identity(device)
            device["classification"] = self._classify_device_intelligence(device)
        devices = self._cluster_logical_identities(devices)
        for device in devices:
            self._reconcile_merged_identity(device)
            self._merge_task_state(device)
            device["rf_quality"] = self._rf_quality(device)
            device["auditability"] = self._auditability_gate(device)
            operation_state = self._device_operation_state(str(device.get("device_key") or ""))
            device["operation_state"] = operation_state
            device["operation_running"] = bool(operation_state.get("status") == "running")
            device["operation_label"] = str(operation_state.get("operation") or "")
            resolution = self._cached_resolution(str(device.get("device_key") or ""))
            device["resolution_state"] = str(resolution.get("state") or "OBSERVED").lower()
            device["materialization_status"] = str(resolution.get("materialization_status") or ("materialized" if device["resolution_state"] in {"materialized", "validation_ready"} else ("candidate_only" if device["resolution_state"] == "candidate" else "failed"))).lower()
            device["resolution_confidence"] = round(float(resolution.get("resolution_confidence") or 0.0), 3)
            device["resolution_method"] = str(resolution.get("resolution_method") or "")
            device["resolution_ambiguity"] = bool(resolution.get("ambiguity"))
            device["resolution_host_path"] = str(resolution.get("host_path") or "")
            device["resolution_host_address"] = str(resolution.get("host_address") or "")
            device["resolution_summary"] = str(resolution.get("detail") or "")
            device["resolution_failure_reason"] = str(resolution.get("failure_reason") or "")
            device["resolution_next_action"] = str(resolution.get("next_action") or "")
            device["resolution_retry_count"] = int(resolution.get("retry_count") or 0)
            device["resolution_last_success"] = resolution.get("last_success_timestamp")
            device["resolution_candidates"] = list(resolution.get("score_breakdown") or [])
            matched_name = str(resolution.get("matched_name") or "").strip()
            if not matched_name and isinstance(device.get("active_validation"), dict):
                matched_name = str(((device.get("active_validation") or {}).get("resolution") or {}).get("matched_name") or "").strip()
            resolution_confidence = float(resolution.get("resolution_confidence") or 0.0)
            if matched_name and not self._looks_like_address_label(matched_name) and resolution_confidence >= 0.32 and str(device.get("name") or "") in {"", "Unknown BLE Device"}:
                device["name"] = self._sanitize_name(matched_name)
                device["identity_reason"] = "host_resolution_name"
                device["identity_confidence"] = "high" if resolution_confidence >= 0.5 else "medium"
                self._reconcile_merged_identity(device)
            active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
            device["gatt_readable_count"] = max(int(device.get("gatt_readable_count") or 0), int(active_validation.get("readable_count") or 0))
            device["gatt_writable_count"] = max(int(device.get("gatt_writable_count") or 0), int(active_validation.get("writable_count") or 0))
            device["vulnerability_matches"] = self._risk_matches(device)
            device["risk"] = self._score_device(device)
            device.update(self._infer_target_pack(device))
            device["tracking_risk"] = self._tracking_risk(device)
            device.update(self._pairable_verdict(device))
            behavioral_tags = sorted(set(device.get("behavioral_tags") or []).union(self._behavioral_anomalies(device)))
            device["behavioral_tags"] = behavioral_tags
            device["anomaly_flags"] = behavioral_tags
            if not device.get("validation_suite"):
                device["validation_suite"] = self._build_validation_suite(device)
            validation_run = device.get("validation_run") if isinstance(device.get("validation_run"), dict) else {}
            device["trust_lifecycle_summary"] = validation_run.get("trust_lifecycle") if isinstance(validation_run.get("trust_lifecycle"), dict) else {}
            device["gatt_exposure_summary"] = validation_run.get("gatt_audit") if isinstance(validation_run.get("gatt_audit"), dict) else {}
            if validation_run.get("behavioral_anomalies"):
                device["anomaly_flags"] = sorted(set(device.get("anomaly_flags") or []).union(validation_run.get("behavioral_anomalies") or []))
            device["recommended_next_steps"] = list(validation_run.get("recommended_next_steps") or [])
            trust_analysis = self._trust_lifecycle_analysis(device)
            gatt_analysis = self._gatt_control_surface_analysis(device)
            device["trust_lifecycle_summary"] = trust_analysis
            device["trust_state_timeline"] = list(trust_analysis.get("timeline") or [])
            device["pairing_method_classification"] = trust_analysis.get("pairing_method_classification") or "unknown"
            device["bond_lifecycle_events"] = trust_analysis.get("bond_lifecycle_events") or {}
            device["reconnect_behavior_summary"] = trust_analysis.get("reconnect_behavior_summary") or "not_attempted"
            device["trust_inconsistencies"] = list(trust_analysis.get("inconsistencies") or [])
            device["gatt_exposure_summary"] = gatt_analysis
            device["gatt_control_surface_analysis"] = gatt_analysis
            device["auto_validation"] = self._auto_validation_summary(device)
            device["weakness_rank"] = self._weakness_rank(device)
            device["tested_state"] = {
                "active_tested": bool((device.get("active_validation") or {}).get("attempted")),
                "suite_tested": int((device.get("validation_suite") or {}).get("scenario_count") or 0) > 0,
                "gatt_tested": bool((device.get("gatt_test") or {}).get("tested_at")),
            }
            if device["resolution_state"] in {"materialized", "validation_ready"} and bool(device.get("connectable")) and str((device.get("auditability") or {}).get("state") or "") == "AUDITABLE":
                device["validation_ready"] = True
            device["classification"] = self._classify_device_intelligence(device)
            classification = device["classification"] if isinstance(device.get("classification"), dict) else {}
            if str(device.get("vendor") or "Unknown") in {"", "Unknown"} and str(classification.get("vendor") or "").strip():
                device["vendor"] = str(classification.get("vendor") or "Unknown")
            if str(device.get("name") or "") in {"", "Unknown BLE Device"} and str(classification.get("matched_device") or "").strip():
                device["name"] = str(classification.get("matched_device"))
            device["classified_type"] = device["classification"].get("device_type") or "Unknown"
            device["classified_protocol"] = device["classification"].get("protocol") or "Unknown"
            device["classified_ecosystem"] = device["classification"].get("ecosystem") or "Unknown"
            device["classification_confidence"] = {
                "score": int(device["classification"].get("confidence") or 0),
                "level": str(device["classification"].get("level") or "LOW"),
            }
            operator_guidance = self._validation_failure_reason(device, device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {})
            device["failure_reason"] = str(operator_guidance.get("reason") or "")
            device["failure_action"] = str(operator_guidance.get("action") or "")
            priority = self._priority_score(device)
            device["priority_score"] = int(priority.get("score") or 0)
            device["recommended_target"] = bool(priority.get("recommended"))
            device["priority_label"] = str(priority.get("label") or "")
            device["session_evidence_timeline"] = self._device_evidence_timeline(device)

        devices = self._apply_identity_graph(devices)
        for device in devices:
            device["session_evidence_timeline"] = self._device_evidence_timeline(device)

        devices = self._collapse_logical_duplicates(devices)
        for device in devices:
            device["session_evidence_timeline"] = self._device_evidence_timeline(device)

        devices.sort(
            key=lambda item: (
                int(item.get("weakness_rank") or 0),
                int((item.get("risk") or {}).get("score") or 0),
                1 if str(item.get("pairable") or "").lower() == "yes" else 0,
                int(item.get("observation_count") or 0),
                float(item.get("last_seen") or 0),
            ),
            reverse=True,
        )
        return devices

    def _build_queue(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        queue: list[dict[str, Any]] = []
        for device in devices[:25]:
            validation = device.get("validation") if isinstance(device.get("validation"), dict) else {}
            active_validation = device.get("active_validation") if isinstance(device.get("active_validation"), dict) else {}
            validation_suite = device.get("validation_suite") if isinstance(device.get("validation_suite"), dict) else {}
            validation_run = device.get("validation_run") if isinstance(device.get("validation_run"), dict) else {}
            queue.append(
                {
                    "device_key": device.get("device_key"),
                    "name": device.get("name"),
                    "vendor": device.get("vendor"),
                    "priority_class": device.get("priority_class"),
                    "auditability": dict(device.get("auditability") or {}),
                    "rf_quality": dict(device.get("rf_quality") or {}),
                    "workflow_state": device.get("workflow_state"),
                    "workflow": device.get("workflow"),
                    "score": (device.get("risk") or {}).get("score") or 0,
                    "priority_score": device.get("priority_score") or 0,
                    "recommended_target": bool(device.get("recommended_target")),
                    "tier": (device.get("risk") or {}).get("tier") or "baseline",
                    "pairing_methods": device.get("pairing_methods") or [],
                    "gatt_writable_count": device.get("gatt_writable_count") or 0,
                    "writable_unauth_count": device.get("writable_unauth_count") or 0,
                    "vulnerability_families": [match.get("family") for match in (device.get("vulnerability_matches") or [])],
                    "exploit_families": device.get("exploit_families") or [],
                    "pairable": device.get("pairable"),
                    "pairable_reason": device.get("pairable_reason"),
                    "tracking_risk": device.get("tracking_risk"),
                    "validation": validation,
                    "active_validation": active_validation,
                    "validation_suite": validation_suite,
                    "trust_lifecycle_summary": validation_run.get("trust_lifecycle") if isinstance(validation_run.get("trust_lifecycle"), dict) else {},
                    "gatt_exposure_summary": validation_run.get("gatt_audit") if isinstance(validation_run.get("gatt_audit"), dict) else {},
                    "recommended_next_steps": list(validation_run.get("recommended_next_steps") or []),
                    "recommended_action": self._recommended_action(device),
                }
            )
        return queue

    def _apply_identity_graph(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        graph = self._build_identity_graph(devices)
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
        if not nodes:
            return devices
        node_by_address: Dict[str, Dict[str, Any]] = {}
        node_by_key: Dict[str, Dict[str, Any]] = {}
        for node in nodes:
            if not isinstance(node, dict):
                continue
            for address in (node.get("rf_addresses") or []):
                if str(address or "").strip():
                    node_by_address[str(address).lower()] = node
            for asset_key in (node.get("linked_asset_keys") or []):
                if str(asset_key or "").strip():
                    node_by_key[str(asset_key).lower()] = node
        for device in devices:
            node = node_by_key.get(str(device.get("device_key") or "").lower()) or node_by_address.get(str(device.get("address") or "").lower())
            if not node:
                continue
            device["identity_id"] = str(node.get("id") or "")
            device["linked_rf_addresses"] = list(node.get("rf_addresses") or [])
            device["identity_confidence_score"] = round(float(node.get("confidence_score") or 0.0), 3)
            device["identity_confidence_label"] = self._confidence_label(device["identity_confidence_score"])
            device["identity_evidence_breakdown"] = dict(node.get("evidence") or {})
            device["identity_ambiguity"] = bool(node.get("ambiguity"))
            device["resolved_host"] = str(node.get("resolved_host") or "")
            device["host_candidates"] = list(node.get("host_candidates") or [])
            device["session_history"] = list(node.get("session_history") or [])
            device["gatt_history"] = list(node.get("gatt_history") or [])
            device["state_history"] = list(node.get("state_history") or [])
        return devices

    def _collapse_logical_duplicates(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not devices:
            return devices

        grouped: Dict[str, List[dict[str, Any]]] = {}
        for device in devices:
            logical_id = str(device.get("logical_device_id") or device.get("identity_id") or device.get("device_key") or "").strip().lower()
            grouped.setdefault(logical_id, []).append(device)

        collapsed: List[dict[str, Any]] = []
        for _, members in grouped.items():
            if len(members) == 1:
                only = dict(members[0])
                only["identity_member_count"] = 1
                only["identity_member_keys"] = [str(only.get("device_key") or "")]
                only["identity_member_addresses"] = sorted({str(only.get("address") or "").lower(), *(str(item).lower() for item in (only.get("linked_rf_addresses") or []) if str(item).strip())})
                collapsed.append(only)
                continue

            primary = max(
                members,
                key=lambda item: (
                    int(item.get("observation_count") or 0),
                    float(item.get("identity_confidence_score") or 0.0),
                    int((item.get("classification") or {}).get("confidence") or 0),
                    int((item.get("risk") or {}).get("score") or 0),
                ),
            )
            merged = dict(primary)
            linked_addresses = sorted(
                {
                    str(item.get("address") or "").lower()
                    for item in members
                    if str(item.get("address") or "").strip()
                }.union(
                    {
                        str(address).lower()
                        for item in members
                        for address in (item.get("linked_rf_addresses") or item.get("linked_addresses") or [])
                        if str(address).strip()
                    }
                )
            )
            merged["observation_count"] = sum(int(item.get("observation_count") or 0) for item in members)
            merged["first_seen"] = min(float(item.get("first_seen") or 0) for item in members)
            merged["last_seen"] = max(float(item.get("last_seen") or 0) for item in members)
            merged["linked_addresses"] = linked_addresses
            merged["linked_rf_addresses"] = linked_addresses
            merged["linked_address_count"] = len(linked_addresses)
            merged["identity_member_count"] = len(members)
            merged["identity_member_keys"] = [str(item.get("device_key") or "") for item in members]
            merged["identity_member_addresses"] = linked_addresses
            merged["duplicate_suspected"] = True
            merged["duplicate_notes"] = f"{len(members)} rows collapsed into one logical identity"
            merged["identity_confidence_score"] = max(float(item.get("identity_confidence_score") or 0.0) for item in members)
            merged["identity_confidence_label"] = self._confidence_label(merged["identity_confidence_score"])
            merged["identity_ambiguity"] = any(bool(item.get("identity_ambiguity")) for item in members)
            merged["identity_evidence_breakdown"] = dict(primary.get("identity_evidence_breakdown") or {})
            merged["session_history"] = sorted(
                [entry for item in members for entry in (item.get("session_history") or []) if isinstance(entry, dict)],
                key=lambda item: float(item.get("timestamp") or 0),
                reverse=True,
            )[:12]
            merged["gatt_history"] = sorted(
                [entry for item in members for entry in (item.get("gatt_history") or []) if isinstance(entry, dict)],
                key=lambda item: float(item.get("timestamp") or 0),
                reverse=True,
            )[:12]
            merged["state_history"] = sorted(
                [entry for item in members for entry in (item.get("state_history") or []) if isinstance(entry, dict)],
                key=lambda item: float(item.get("timestamp") or 0),
            )[-12:]
            merged["resolution_candidates"] = list(primary.get("resolution_candidates") or [])
            merged["workflow"] = primary.get("workflow") or "monitor"
            merged["workflow_state"] = primary.get("workflow_state") or "monitoring"
            collapsed.append(merged)
        return collapsed

    def _recommended_action(self, device: dict[str, Any]) -> str:
        gate = self._auditability_gate(device)
        if gate["state"] == "NOT_AUDITABLE":
            return gate["action"]
        if gate["state"] == "LIMITED":
            return gate["action"]
        workflow = str(device.get("workflow") or "monitor")
        tier = str((device.get("risk") or {}).get("tier") or "baseline")
        resolution_state = str(device.get("resolution_state") or "observed")
        services_resolved = bool((device.get("active_validation") or {}).get("services_resolved"))
        if workflow == "validate":
            if resolution_state not in {"materialized", "validation_ready"}:
                return "Run targeted host discovery until this asset materializes as a BlueZ Device1 target."
            if not services_resolved:
                return "Repeat the active test until BlueZ resolves services, then run the full validation suite."
            if str((device.get("active_validation") or {}).get("connect_result") or "") in {"connected", "paired"}:
                return "Review the active product test, map exposed services, and verify whether sensitive GATT operations require authentication."
            return "Move this device into approved lab validation and enumerate pairing, GATT, and reconnect behavior."
        if workflow == "assess":
            return "Keep this device in the red-team assessment queue and collect more fingerprinting evidence."
        if tier == "critical":
            return "Move this device into approved lab validation and review pairing + GATT authorization immediately."
        if tier == "high":
            return "Collect pairing telemetry and enumerate high-risk GATT surfaces before the next assessment cycle."
        if device.get("pairing_methods"):
            return "Keep passive watch and baseline trust changes across pairing and bond events."
        return "Continue passive inventory and wait for more BLE metadata before active validation."

    def _summary(self, devices: list[dict[str, Any]], sensors: list[dict[str, Any]]) -> dict[str, Any]:
        vulnerability_counter = Counter()
        priority_counter = Counter()
        classification_counter = Counter()
        protocol_counter = Counter()
        ecosystem_counter = Counter()
        auditability_counter = Counter()
        rf_quality_counter = Counter()
        identity_payload = self._identity_graph_payload()
        identity_summary = (identity_payload.get("summary") if isinstance(identity_payload, dict) else {}) or {}
        for device in devices:
            priority_counter[str(device.get("priority_class") or "general")] += 1
            auditability_counter[str((device.get("auditability") or {}).get("state") or "UNKNOWN")] += 1
            rf_quality_counter[str((device.get("rf_quality") or {}).get("label") or "WEAK")] += 1
            classification = device.get("classification") if isinstance(device.get("classification"), dict) else {}
            classification_counter[str(classification.get("device_type") or "Unknown")] += 1
            protocol_counter[str(classification.get("protocol") or "Unknown")] += 1
            ecosystem_counter[str(classification.get("ecosystem") or "Unknown")] += 1
            for match in device.get("vulnerability_matches") or []:
                vulnerability_counter[str(match.get("family") or "Bluetooth Exposure")] += 1

        return {
            "device_count": len(devices),
            "active_sensor_count": len(sensors),
            "critical_devices": sum(1 for device in devices if (device.get("risk") or {}).get("tier") == "critical"),
            "high_risk_devices": sum(1 for device in devices if (device.get("risk") or {}).get("tier") in {"critical", "high"}),
            "pairing_risk_devices": sum(1 for device in devices if device.get("pairing_methods")),
            "gatt_exposure_devices": sum(1 for device in devices if int(device.get("gatt_writable_count") or 0) > 0),
            "named_devices": sum(1 for device in devices if str(device.get("name") or "") not in {"", "Unknown BLE Device"}),
            "materialized_devices": sum(1 for device in devices if str(device.get("resolution_state") or "") in {"materialized", "validation_ready"}),
            "candidate_devices": sum(1 for device in devices if str(device.get("materialization_status") or "") == "candidate_only"),
            "failed_materialization_devices": sum(1 for device in devices if str(device.get("materialization_status") or "") == "failed"),
            "validation_ready_devices": sum(1 for device in devices if bool(device.get("validation_ready"))),
            "auditable_devices": sum(1 for device in devices if str((device.get("auditability") or {}).get("state") or "") == "AUDITABLE"),
            "limited_devices": sum(1 for device in devices if str((device.get("auditability") or {}).get("state") or "") == "LIMITED"),
            "not_auditable_devices": sum(1 for device in devices if str((device.get("auditability") or {}).get("state") or "") == "NOT_AUDITABLE"),
            "recommended_targets": sum(1 for device in devices if bool(device.get("recommended_target"))),
            "validated_devices": sum(1 for device in devices if str((device.get("auto_validation") or {}).get("status") or "") in {"validated", "partial", "weak"}),
            "active_tested_devices": sum(1 for device in devices if bool((device.get("active_validation") or {}).get("attempted"))),
            "validation_suite_devices": sum(1 for device in devices if int((device.get("validation_suite") or {}).get("scenario_count") or 0) > 0),
            "tracking_risk_devices": sum(1 for device in devices if str(device.get("tracking_risk") or "") == "high"),
            "assigned_targets": sum(1 for device in devices if str(device.get("workflow") or "monitor") != "monitor"),
            "identity_nodes": int(identity_summary.get("node_count") or 0),
            "identity_correlated_nodes": int(identity_summary.get("correlated_nodes") or 0),
            "identity_resolved_hosts": int(identity_summary.get("resolved_hosts") or 0),
            "priority_classes": dict(priority_counter),
            "auditability": dict(auditability_counter),
            "rf_quality": dict(rf_quality_counter),
            "classified_types": dict(classification_counter),
            "classified_protocols": dict(protocol_counter),
            "ecosystems": dict(ecosystem_counter),
            "top_vulnerability_families": vulnerability_counter.most_common(6),
        }

    def start(
        self,
        profile: str = DEFAULT_PROFILE,
        mission: str = "asset_discovery",
        lab_mode: bool = False,
        classic_sidecar: bool = False,
        sensor_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        self.active = True
        self.started_at = time.time()
        self.last_profile = str(profile or self.DEFAULT_PROFILE)
        self.last_mission = str(mission or "asset_discovery")
        self.lab_mode = bool(lab_mode)
        self.classic_sidecar = bool(classic_sidecar)
        self.sensor_selection = [str(item) for item in (sensor_ids or []) if str(item).strip()]
        self.last_error = ""
        self._reset_scan_state()
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": self.started_at,
                "event_type": "session_start",
                "profile": self.last_profile,
                "mission": self.last_mission,
                "lab_mode": self.lab_mode,
                "classic_sidecar": self.classic_sidecar,
                "sensor_ids": self.sensor_selection,
            },
        )
        return self.get_status()

    def _live_hunt_loop(self, scan_seconds: int, stop_event: threading.Event) -> None:
        cycle_count = 0
        self._set_live_hunt_state(
            active=True,
            status="running",
            detail="Live Hunt online and waiting for Bluetooth advertisements.",
            scan_seconds=scan_seconds,
            heartbeat_at=time.time(),
        )
        try:
            while self.active and not stop_event.is_set():
                cycle_count += 1
                cycle_started_at = time.time()
                self._set_live_hunt_state(
                    active=True,
                    status="running",
                    detail=f"Cycle {cycle_count} collecting live Bluetooth advertisements.",
                    scan_seconds=scan_seconds,
                    cycle_count=cycle_count,
                    last_cycle_started_at=cycle_started_at,
                    heartbeat_at=cycle_started_at,
                    stopped_at=None,
                )
                scan_result = self.run_scan(
                    duration_seconds=scan_seconds,
                    stop_event=stop_event,
                    observation_sink=self.record_observation,
                )
                devices = self._aggregate_devices()
                last_cycle_completed_at = time.time()
                observation_count = int(((scan_result.get("scan") or {}).get("observation_count")) or 0)
                if stop_event.is_set() or not self.active:
                    break
                self._set_live_hunt_state(
                    active=True,
                    status="running",
                    detail=(
                        f"Cycle {cycle_count} retained {observation_count} observations. "
                        f"{len(devices)} device(s) visible for operator audit."
                    ),
                    cycle_count=cycle_count,
                    last_cycle_completed_at=last_cycle_completed_at,
                    last_cycle_observation_count=observation_count,
                    last_cycle_device_count=len(devices),
                    heartbeat_at=last_cycle_completed_at,
                )
                stop_event.wait(0.6)
        except Exception as exc:
            self.last_error = str(exc)
            self._set_live_hunt_state(
                active=False,
                status="error",
                detail=f"Live Hunt stopped: {exc}",
                stopped_at=time.time(),
                heartbeat_at=time.time(),
            )
            self._append_jsonl(
                self.timeline_log,
                {
                    "timestamp": time.time(),
                    "event_type": "live_hunt_error",
                    "detail": str(exc),
                },
            )
        finally:
            stopped_at = time.time()
            if str(self._live_hunt_snapshot().get("status") or "") != "error":
                devices = self._aggregate_devices()
                self._set_live_hunt_state(
                    active=False,
                    status="idle" if self.active else "stopped",
                    detail=(
                        "Live Hunt paused. Devices remain retained for manual audit."
                        if self.active
                        else "Live Hunt stopped with the BLE NR5 session."
                    ),
                    last_cycle_completed_at=stopped_at,
                    last_cycle_device_count=len(devices),
                    stopped_at=stopped_at,
                    heartbeat_at=stopped_at,
                )

    def start_live_hunt(self, scan_seconds: int | float = DEFAULT_SCAN_SECONDS) -> Dict[str, Any]:
        normalized_seconds = max(4, min(300, int(scan_seconds or self.DEFAULT_SCAN_SECONDS)))
        if not self.active:
            self.active = True
            if not self.started_at:
                self.started_at = time.time()
        with self._live_hunt_lock:
            if self._live_hunt_thread and self._live_hunt_thread.is_alive():
                snapshot = dict(self.live_hunt_state)
                return {"status": "already_running", "live_hunt": snapshot}
            self._live_hunt_stop_event = threading.Event()
            now = time.time()
            self.live_hunt_state = {
                **self._default_live_hunt_state(),
                "active": True,
                "status": "arming",
                "detail": "Live Hunt arming the nRF52840 Bluetooth collector.",
                "scan_seconds": normalized_seconds,
                "started_at": now,
                "heartbeat_at": now,
            }
            self._live_hunt_thread = threading.Thread(
                target=self._live_hunt_loop,
                args=(normalized_seconds, self._live_hunt_stop_event),
                daemon=True,
                name="ble-nr5-live-hunt",
            )
            self._live_hunt_thread.start()
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": time.time(),
                "event_type": "live_hunt_start",
                "scan_seconds": normalized_seconds,
            },
        )
        return {"status": "started", "live_hunt": self._live_hunt_snapshot()}

    def stop_live_hunt(self, reason: str = "operator_stop") -> Dict[str, Any]:
        with self._live_hunt_lock:
            thread = self._live_hunt_thread
            if not thread or not thread.is_alive():
                snapshot = dict(self.live_hunt_state)
                snapshot["active"] = False
                if str(snapshot.get("detail") or "").strip() in {"", "Live Hunt idle"}:
                    snapshot["detail"] = "Live Hunt is already idle."
                self.live_hunt_state = snapshot
                return {"status": "idle", "live_hunt": snapshot}
            stop_event = self._live_hunt_stop_event
            snapshot = dict(self.live_hunt_state)
            snapshot.update(
                {
                    "active": True,
                    "status": "stopping",
                    "detail": "Stop requested. Freezing the live Bluetooth hunt for operator audit.",
                    "heartbeat_at": time.time(),
                }
            )
            self.live_hunt_state = snapshot
        stop_event.set()
        thread.join(timeout=6.0)
        with self._live_hunt_lock:
            if self._live_hunt_thread is thread and not thread.is_alive():
                self._live_hunt_thread = None
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": time.time(),
                "event_type": "live_hunt_stop",
                "reason": reason,
            },
        )
        return {"status": "stopped", "live_hunt": self._live_hunt_snapshot()}

    def stop(self) -> dict[str, Any]:
        self.stop_live_hunt(reason="session_stop")
        now = time.time()
        self.active = False
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": now,
                "event_type": "session_stop",
                "profile": self.last_profile,
                "mission": self.last_mission,
            },
        )
        return self.get_status()

    def clear_results(self) -> dict[str, Any]:
        self.stop_live_hunt(reason="clear_results")
        for path in (self.observation_log, self.timeline_log, self.task_state_path, self.identity_graph_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
        self._save_resolution_cache_map({})
        self._identity_graph_cache = None
        with self._device_operation_lock:
            self._device_operations = {}
        with self._target_session_lock:
            self._target_sessions = {}
        for lock_path in self.operation_lock_dir.glob("*.lock"):
            try:
                lock_path.unlink(missing_ok=True)
            except Exception:
                pass
        for lock_path in self.target_session_lock_dir.glob("*.lock"):
            try:
                lock_path.unlink(missing_ok=True)
            except Exception:
                pass
        self._reset_scan_state()
        self.last_scan = {}
        self.gatt_engine_state = {
            "status": "idle",
            "device_key": "",
            "device_name": "",
            "summary": "GATT engine idle",
            "stages": [],
            "updated_at": time.time(),
        }
        self.identity_engine_state = {
            "status": "idle",
            "summary": "Identity correlation engine idle",
            "stages": [],
            "node_count": 0,
            "resolved_hosts": 0,
            "correlated_nodes": 0,
            "updated_at": time.time(),
        }
        self.hard_test_state = {
            "status": "idle",
            "device_key": "",
            "device_name": "",
            "summary": "Hard BLE test idle",
            "stages": [],
            "updated_at": time.time(),
        }
        self.live_hunt_state = self._default_live_hunt_state()
        self._live_hunt_thread = None
        self._live_hunt_stop_event = threading.Event()
        return {
            "status": "cleared",
            "service": "ble_nr5",
        }

    def record_observation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        observation = {
            "timestamp": float(payload.get("timestamp") or now),
            "sensor_id": str(payload.get("sensor_id") or "nr5-1"),
            "channel": payload.get("channel") if payload.get("channel") is not None else 37,
            "channel_set": [int(item) for item in (payload.get("channel_set") or []) if item is not None],
            "address": str(payload.get("address") or "").strip(),
            "address_type": str(payload.get("address_type") or "unknown"),
            "name": str(payload.get("name") or "Unknown BLE Device"),
            "manufacturer_data_hash": str(payload.get("manufacturer_data_hash") or ""),
            "manufacturer_company_id": payload.get("manufacturer_company_id"),
            "manufacturer_data_prefix": str(payload.get("manufacturer_data_prefix") or ""),
            "service_uuids": [str(item) for item in (payload.get("service_uuids") or [])],
            "service_uuid_signature": str(payload.get("service_uuid_signature") or ""),
            "service_data_uuids": [str(item) for item in (payload.get("service_data_uuids") or [])],
            "rssi": payload.get("rssi"),
            "tx_power": payload.get("tx_power"),
            "packet_type": str(payload.get("packet_type") or "advertisement"),
            "packet_types": [str(item) for item in (payload.get("packet_types") or [])],
            "packet_length": int(payload.get("packet_length") or 0),
            "adv_flags": payload.get("adv_flags"),
            "ad_structure_count": int(payload.get("ad_structure_count") or 0),
            "connectable": bool(payload.get("connectable")),
            "scannable": bool(payload.get("scannable")),
            "scan_response_seen": bool(payload.get("scan_response_seen")),
            "observation_count": int(payload.get("observation_count") or 1),
            "frame_count": int(payload.get("frame_count") or payload.get("observation_count") or 1),
            "pairing_method": str(payload.get("pairing_method") or ""),
            "bond_created": bool(payload.get("bond_created")),
            "bond_updated": bool(payload.get("bond_updated")),
            "repair_flag": bool(payload.get("repair_flag")),
            "pairing_failure": bool(payload.get("pairing_failure")),
            "silent_pairing_pattern": bool(payload.get("silent_pairing_pattern")),
            "gatt_readable_count": int(payload.get("gatt_readable_count") or 0),
            "gatt_writable_count": int(payload.get("gatt_writable_count") or 0),
            "writable_unauth_count": int(payload.get("writable_unauth_count") or 0),
            "sensitive_surface_count": int(payload.get("sensitive_surface_count") or 0),
            "priority_class": str(payload.get("priority_class") or "general"),
            "priority_classes": [str(item) for item in (payload.get("priority_classes") or [])],
            "device_type": str(payload.get("device_type") or "bluetooth device"),
            "identity_confidence": str(payload.get("identity_confidence") or "low"),
            "identity_reason": str(payload.get("identity_reason") or "rotating_address_only"),
            "vendor_confidence": str(payload.get("vendor_confidence") or "low"),
            "category_confidence": str(payload.get("category_confidence") or "low"),
            "behavioral_tags": [str(item) for item in (payload.get("behavioral_tags") or [])],
            "vendor": str(payload.get("vendor") or payload.get("manufacturer") or ""),
            "verdict": str(payload.get("verdict") or "Observed"),
            "stable_id": str(payload.get("stable_id") or ""),
            "asset_key": str(payload.get("asset_key") or ""),
        }
        self._append_jsonl(self.observation_log, observation)
        self._append_jsonl(
            self.timeline_log,
            {
                "timestamp": observation["timestamp"],
                "event_type": "observation",
                "sensor_id": observation["sensor_id"],
                "address": observation["address"],
                "name": observation["name"],
                "packet_type": observation["packet_type"],
                "frame_count": observation["frame_count"],
                "pairing_method": observation["pairing_method"],
                "verdict": observation["verdict"],
            },
        )
        self._identity_graph_cache = None
        return {"status": "recorded", "observation": observation}

    def get_devices(self) -> Dict[str, Any]:
        devices = self._aggregate_devices()
        return {
            "count": len(devices),
            "devices": devices,
        }

    def get_queue(self) -> Dict[str, Any]:
        devices = self._aggregate_devices()
        queue = self._build_queue(devices)
        return {
            "count": len(queue),
            "queue": queue,
        }

    def get_timeline(self, limit: int = 80) -> Dict[str, Any]:
        events = self._read_jsonl(self.timeline_log)
        return {
            "count": len(events),
            "events": events[-max(1, int(limit)) :],
        }

    def get_knowledge(self) -> Dict[str, Any]:
        fingerprint_summary = self.ble_intelligence_engine.database_summary()
        return {
            "loaded": bool(self._knowledge_base) or bool(fingerprint_summary.get("loaded")),
            "knowledge_base": self._knowledge_base,
            "fingerprint_database": self.ble_intelligence_engine.database,
            "fingerprint_summary": fingerprint_summary,
        }

    def get_validation_framework(self) -> Dict[str, Any]:
        return {
            "modules": self.validation_engine.module_catalog(),
            "tool_catalog": self.validation_engine.tool_catalog(),
        }

    def get_validation_runs(self, device_key: str = "") -> Dict[str, Any]:
        runs = self.validation_engine.list_runs(device_key=device_key)
        return {"count": len(runs), "runs": runs}

    def get_status(self) -> Dict[str, Any]:
        sensors = self._discover_sensors()
        devices = self._aggregate_devices()
        summary = self._summary(devices, sensors)
        tool_readiness = self._tool_readiness()
        identity_graph = self._identity_graph_payload()
        return {
            "service": "ble_nr5",
            "version": self.VERSION,
            "sensor_ready": any(bool(sensor.get("collector_ready")) for sensor in sensors),
            "active": self.active,
            "started_at": self.started_at,
            "profile": self.last_profile,
            "mission": self.last_mission,
            "lab_mode": self.lab_mode,
            "classic_sidecar": self.classic_sidecar,
            "sensor_selection": self.sensor_selection,
            "channels": list(self.DEFAULT_CHANNELS),
            "sensor_count": len(sensors),
            "sensors": sensors,
            "summary": summary,
            "last_error": self.last_error,
            "scan_stages": self.scan_stages,
            "last_scan": self.last_scan,
            "active_tools": self.active_tools,
            "tool_readiness": tool_readiness,
            "workflow_tasks": self.get_tasks().get("tasks") or [],
            "knowledge_loaded": bool(self._knowledge_base) or bool(self.ble_intelligence_engine.devices),
            "profiles": self._knowledge_base.get("profiles") or [],
            "validation_scenarios": list(self.VALIDATION_SCENARIOS.values()),
            "validation_framework": self.get_validation_framework(),
            "mission_modules": self._knowledge_base.get("mission_modules") or [],
            "priority_classes": self._knowledge_base.get("priority_classes") or [],
            "fingerprint_summary": self.ble_intelligence_engine.database_summary(),
            "live_hunt": self._live_hunt_snapshot(),
            "gatt_engine_state": self.gatt_engine_state,
            "identity_engine_state": self.identity_engine_state,
            "hard_test_state": self.hard_test_state,
            "identity_graph_summary": (identity_graph.get("summary") if isinstance(identity_graph, dict) else {}) or {},
        }
