from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from shutil import which
from typing import Any, Dict, List


class MonitorManager:
    PREFERRED_INTERFACE = "wlan1"

    def __init__(self) -> None:
        preferred = str(os.environ.get("WIFI_MK7_PREFERRED_INTERFACE", self.PREFERRED_INTERFACE) or "").strip()
        self.PREFERRED_INTERFACE = preferred or self.PREFERRED_INTERFACE
        self.iw_path = which("iw") or self._fallback_path("/usr/sbin/iw")
        self.ip_path = which("ip") or self._fallback_path("/usr/sbin/ip")
        self.sudo_path = which("sudo") or self._fallback_path("/usr/bin/sudo")
        self.passwordless_sudo = self._detect_passwordless_sudo()
        self.last_error = ""

    @staticmethod
    def _fallback_path(candidate: str) -> str | None:
        return candidate if Path(candidate).exists() else None

    def _detect_passwordless_sudo(self) -> bool:
        if not self.sudo_path or os.geteuid() == 0:
            return False
        try:
            result = subprocess.run(
                [self.sudo_path, "-n", "true"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except Exception:
            return False
        return result.returncode == 0

    @staticmethod
    def _needs_privilege_retry(detail: str) -> bool:
        lowered = detail.lower()
        return any(
            marker in lowered
            for marker in (
                "operation not permitted",
                "permission denied",
                "not authorized",
                "generic netlink",
            )
        )

    @staticmethod
    def _dedupe_details(details: List[str]) -> List[str]:
        seen: set[str] = set()
        unique: List[str] = []
        for detail in details:
            text = str(detail or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(text)
        return unique

    def _privilege_remediation(self, interface: str = "") -> str:
        target = str(interface or self.PREFERRED_INTERFACE).strip() or "the WiFi adapter"
        if os.geteuid() == 0 or self.passwordless_sudo:
            return (
                f"Restart the backend so it can retry monitor-mode setup on {target} with the current privilege state."
            )
        return (
            f"Start the backend with `sudo ./scripts/start.sh` or grant CAP_NET_ADMIN/root privileges to the backend process for {target}."
        )

    def _augment_privilege_error(self, detail: str, requirement: str, interface: str = "") -> str:
        text = str(detail or "").strip() or requirement
        if not self._needs_privilege_retry(text):
            return text
        if requirement.lower() not in text.lower():
            text = f"{text} {requirement}".strip()
        remediation = self._privilege_remediation(interface)
        if remediation and remediation.lower() not in text.lower():
            text = f"{text} {remediation}".strip()
        return text

    def _run(self, cmd: List[str], timeout: int = 8) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if (
            result.returncode != 0
            and self.passwordless_sudo
            and self.sudo_path
            and cmd
            and cmd[0] in {self.iw_path, self.ip_path}
        ):
            detail = (result.stderr or result.stdout or "").strip()
            if self._needs_privilege_retry(detail):
                return subprocess.run(
                    [self.sudo_path, "-n", *cmd],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
        return result

    def available(self) -> bool:
        return bool(self.iw_path and self.ip_path)

    def list_interfaces(self) -> List[Dict[str, Any]]:
        if not self.iw_path:
            self.last_error = "iw is not installed on this host."
            return []

        result = self._run([self.iw_path, "dev"])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "Unable to query WiFi interfaces.").strip()
            lowered = detail.lower()
            if "generic netlink" in lowered:
                detail = f"{detail} The process does not have enough access to query nl80211 on this host."
            detail = self._augment_privilege_error(
                detail,
                "Root or CAP_NET_ADMIN privileges are required to query WiFi interfaces.",
            )
            self.last_error = detail
            return []
        self.last_error = ""
        interfaces: List[Dict[str, Any]] = []
        current: Dict[str, Any] | None = None
        current_phy = ""

        for raw_line in (result.stdout or "").splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if stripped.startswith("phy#"):
                if current:
                    interfaces.append(current)
                    current = None
                current_phy = stripped
                continue
            if stripped.startswith("Interface "):
                if current:
                    interfaces.append(current)
                current = {
                    "phy": current_phy,
                    "name": stripped.split("Interface ", 1)[1].strip(),
                    "type": "",
                    "addr": "",
                    "ssid": "",
                    "channel": None,
                }
                continue
            if not current:
                continue
            if stripped.startswith("addr "):
                current["addr"] = stripped.split("addr ", 1)[1].strip()
            elif stripped.startswith("type "):
                current["type"] = stripped.split("type ", 1)[1].strip()
            elif stripped.startswith("ssid "):
                current["ssid"] = stripped.split("ssid ", 1)[1].strip()
            elif stripped.startswith("channel "):
                match = re.search(r"channel\s+(\d+)\s+\((\d+)\s+MHz\)", stripped)
                if match:
                    current["channel"] = int(match.group(1))
                    current["frequency_mhz"] = int(match.group(2))

        if current:
            interfaces.append(current)

        return interfaces

    def choose_interface(self) -> Dict[str, Any] | None:
        candidates = [item for item in self.list_interfaces() if item.get("name") == self.PREFERRED_INTERFACE]
        if not candidates:
            return None
        preferred = next((item for item in candidates if item.get("type") == "managed"), None)
        return preferred or candidates[0]

    def list_candidate_sensors(self, preferred_interfaces: List[str] | None = None) -> List[Dict[str, Any]]:
        interfaces = self.list_interfaces()
        preferred = [str(item).strip() for item in (preferred_interfaces or [self.PREFERRED_INTERFACE]) if str(item).strip()]
        managed_candidates = [item for item in interfaces if item.get("name", "").startswith("wlan") and item.get("type") == "managed"]
        if preferred:
            managed_candidates = [item for item in managed_candidates if item.get("name") in preferred]
        sensors: List[Dict[str, Any]] = []
        for interface in managed_candidates:
            monitor_name = f"{interface['name']}mon"
            existing_monitor = next((item for item in interfaces if item.get("name") == monitor_name), None)
            phy_support = self._phy_support(interface.get("phy", ""))
            sensors.append(
                {
                    "available": True,
                    "detail": f"Detected {interface['name']} on {interface.get('phy') or 'unknown phy'}.",
                    "base_interface": interface["name"],
                    "monitor_interface": existing_monitor.get("name") if existing_monitor else None,
                    "monitor_mode_enabled": bool(existing_monitor),
                    "bands": phy_support.get("bands", []),
                    "monitor_supported": bool(phy_support.get("monitor_supported")),
                    "phy": interface.get("phy"),
                    "addr": interface.get("addr"),
                    "preferred_interface": self.PREFERRED_INTERFACE,
                }
            )
        return sensors

    def _phy_support(self, phy: str) -> Dict[str, Any]:
        if not self.iw_path or not phy:
            return {"monitor_supported": False, "bands": []}

        result = self._run([self.iw_path, "list"])
        text = result.stdout or ""
        bands: List[str] = []
        if "5180.0 MHz" in text or "5240.0 MHz" in text or "5745.0 MHz" in text:
            bands.append("5 GHz")
        if "2412.0 MHz" in text or "2437.0 MHz" in text:
            bands.append("2.4 GHz")
        return {
            "monitor_supported": "* monitor" in text or " monitor" in text,
            "bands": bands,
        }

    def detect_sensor(self) -> Dict[str, Any]:
        interfaces = self.list_interfaces()
        preferred_present = any(item.get("name") == self.PREFERRED_INTERFACE for item in interfaces)
        interface = self.choose_interface()
        if not interface:
            return {
                "available": False,
                "detail": self.last_error or f"Preferred MK7AC adapter {self.PREFERRED_INTERFACE} not detected. Connect the MK7AC adapter.",
                "base_interface": None,
                "monitor_interface": None,
                "monitor_mode_enabled": False,
                "bands": [],
                "monitor_supported": False,
                "preferred_interface": self.PREFERRED_INTERFACE,
            }

        monitor_name = f"{interface['name']}mon"
        existing_monitor = next((item for item in interfaces if item.get("name") == monitor_name), None)
        phy_support = self._phy_support(interface.get("phy", ""))
        detail = f"Detected {interface['name']} on {interface.get('phy') or 'unknown phy'}."
        if interface["name"] == self.PREFERRED_INTERFACE:
            detail = f"Detected preferred MK7AC adapter {interface['name']} on {interface.get('phy') or 'unknown phy'}."
        return {
            "available": True,
            "detail": detail,
            "base_interface": interface["name"],
            "monitor_interface": existing_monitor.get("name") if existing_monitor else None,
            "monitor_mode_enabled": bool(existing_monitor),
            "bands": phy_support.get("bands", []),
            "monitor_supported": bool(phy_support.get("monitor_supported")),
            "phy": interface.get("phy"),
            "addr": interface.get("addr"),
            "preferred_interface": self.PREFERRED_INTERFACE,
        }

    def ensure_monitor_interface(self) -> Dict[str, Any]:
        sensor = self.detect_sensor()
        if not sensor.get("available"):
            return sensor
        if sensor.get("monitor_interface"):
            sensor["detail"] = f"Monitor interface {sensor['monitor_interface']} ready."
            return sensor
        if not self.available():
            sensor["detail"] = "iw/ip tooling not available on this host."
            return sensor

        base_interface = sensor.get("base_interface")
        phy = sensor.get("phy")
        monitor_interface = f"{base_interface}mon"
        if not base_interface or not phy:
            sensor["detail"] = "Unable to resolve WiFi interface or phy."
            return sensor
        if not sensor.get("monitor_supported"):
            sensor["detail"] = f"Adapter {base_interface} does not report monitor-mode support."
            return sensor

        phy_name = str(phy).replace("#", "")
        add_result = self._run([self.iw_path, "phy", phy_name, "interface", "add", monitor_interface, "type", "monitor"])
        if add_result.returncode != 0:
            detail = (add_result.stderr or add_result.stdout or "Failed to create monitor interface.").strip()
            detail = self._augment_privilege_error(
                detail,
                f"Root or CAP_NET_ADMIN privileges are required to enable monitor mode on {base_interface}.",
                base_interface,
            )
            sensor["detail"] = detail
            return sensor

        up_result = self._run([self.ip_path, "link", "set", monitor_interface, "up"])
        if up_result.returncode != 0:
            detail = (up_result.stderr or up_result.stdout or f"Failed to bring up {monitor_interface}.").strip()
            detail = self._augment_privilege_error(
                detail,
                f"Root or CAP_NET_ADMIN privileges are required to bring up {monitor_interface}.",
                base_interface,
            )
            sensor["detail"] = detail
            return sensor
        sensor = self.detect_sensor()
        if sensor.get("monitor_interface"):
            sensor["detail"] = f"Monitor interface {sensor['monitor_interface']} created."
        return sensor

    def ensure_monitor_interfaces(self, preferred_interfaces: List[str] | None = None) -> Dict[str, Any]:
        requested = [str(item).strip() for item in (preferred_interfaces or []) if str(item).strip()]
        sensors = self.list_candidate_sensors(requested)
        prepared: List[Dict[str, Any]] = []
        errors: List[str] = []

        if not sensors and requested:
            return {
                "available": False,
                "detail": f"Requested WiFi adapters not detected: {', '.join(requested)}",
                "base_interface": None,
                "monitor_interface": None,
                "monitor_interfaces": [],
                "monitor_mode_enabled": False,
                "bands": [],
                "monitor_supported": False,
                "preferred_interface": self.PREFERRED_INTERFACE,
                "sensors": [],
            }

        for sensor in sensors or [self.detect_sensor()]:
            base_interface = sensor.get("base_interface")
            if not sensor.get("available"):
                if sensor.get("detail"):
                    errors.append(str(sensor.get("detail")))
                continue
            if sensor.get("monitor_interface"):
                sensor["detail"] = f"Monitor interface {sensor['monitor_interface']} ready."
                prepared.append(sensor)
                continue
            if requested and base_interface not in requested:
                continue
            if not self.available():
                sensor["detail"] = "iw/ip tooling not available on this host."
                errors.append(sensor["detail"])
                continue
            if not base_interface or not sensor.get("phy"):
                sensor["detail"] = "Unable to resolve WiFi interface or phy."
                errors.append(sensor["detail"])
                continue
            if not sensor.get("monitor_supported"):
                sensor["detail"] = f"Adapter {base_interface} does not report monitor-mode support."
                errors.append(sensor["detail"])
                continue

            phy_name = str(sensor.get("phy")).replace("#", "")
            monitor_interface = f"{base_interface}mon"
            add_result = self._run([self.iw_path, "phy", phy_name, "interface", "add", monitor_interface, "type", "monitor"])
            if add_result.returncode != 0:
                detail = (add_result.stderr or add_result.stdout or "Failed to create monitor interface.").strip()
                detail = self._augment_privilege_error(
                    detail,
                    f"Root or CAP_NET_ADMIN privileges are required to enable monitor mode on {base_interface}.",
                    base_interface,
                )
                sensor["detail"] = detail
                errors.append(detail)
                continue

            up_result = self._run([self.ip_path, "link", "set", monitor_interface, "up"])
            if up_result.returncode != 0:
                detail = (up_result.stderr or up_result.stdout or f"Failed to bring up {monitor_interface}.").strip()
                detail = self._augment_privilege_error(
                    detail,
                    f"Root or CAP_NET_ADMIN privileges are required to bring up {monitor_interface}.",
                    base_interface,
                )
                sensor["detail"] = detail
                errors.append(detail)
                continue

            refreshed = next((item for item in self.list_candidate_sensors([base_interface]) if item.get("base_interface") == base_interface), sensor)
            refreshed["detail"] = f"Monitor interface {refreshed.get('monitor_interface') or monitor_interface} created."
            prepared.append(refreshed)

        primary = prepared[0] if prepared else (sensors[0] if sensors else self.detect_sensor())
        detail_rows = self._dedupe_details([primary.get("detail") if primary else "", *errors[:2]])
        privilege_required = bool(not prepared and any(self._needs_privilege_retry(row) for row in detail_rows))
        return {
            **primary,
            "monitor_interfaces": [item.get("monitor_interface") for item in prepared if item.get("monitor_interface")],
            "sensors": prepared if prepared else sensors,
            "detail": "; ".join(detail_rows),
            "privilege_required": privilege_required,
            "remediation": self._privilege_remediation(primary.get("base_interface")) if primary and privilege_required else "",
        }
