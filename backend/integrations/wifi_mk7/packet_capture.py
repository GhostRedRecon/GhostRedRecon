from __future__ import annotations

import os
import subprocess
import time
import tempfile
import math
from pathlib import Path
from shutil import which
from typing import Any, Dict, List

from backend.integrations.wifi_mk7.frame_parser import FrameParser


class PacketCaptureEngine:
    def __init__(self, root_dir: Path) -> None:
        self.iw_path = which("iw") or self._fallback_path("/usr/sbin/iw")
        self.dumpcap_path = which("dumpcap") or self._fallback_path("/usr/bin/dumpcap")
        self.tcpdump_path = which("tcpdump") or self._fallback_path("/usr/bin/tcpdump")
        self.tshark_path = which("tshark") or self._fallback_path("/usr/bin/tshark")
        self.sudo_path = which("sudo") or self._fallback_path("/usr/bin/sudo")
        self.passwordless_sudo = self._detect_passwordless_sudo()
        self.capture_dir = root_dir / "logs" / "wifi_mk7"
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_capture_dir = Path(tempfile.gettempdir()) / "ghostrecon_wifi_mk7"
        try:
            self.fallback_capture_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.parser = FrameParser()

    @staticmethod
    def _fallback_path(candidate: str) -> str | None:
        return candidate if Path(candidate).exists() else None

    def available(self) -> bool:
        return bool(self.iw_path and self.tshark_path and (self.dumpcap_path or self.tcpdump_path))

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
        return any(marker in lowered for marker in ("operation not permitted", "permission denied", "not authorized"))

    def _writable_capture_dirs(self) -> List[Path]:
        writable: List[Path] = []
        for candidate in (self.capture_dir, self.fallback_capture_dir):
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                probe = candidate / ".write_probe"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
                writable.append(candidate)
            except Exception:
                continue
        return writable

    def tool_status(self) -> Dict[str, Any]:
        return {
            "iw": {"available": bool(self.iw_path), "path": self.iw_path or "", "active": True},
            "dumpcap": {"available": bool(self.dumpcap_path), "path": self.dumpcap_path or "", "active": True},
            "tcpdump": {"available": bool(self.tcpdump_path), "path": self.tcpdump_path or "", "active": True},
            "tshark": {"available": bool(self.tshark_path), "path": self.tshark_path or "", "active": True},
        }

    def _pick_capture_dir(self) -> Path:
        writable = self._writable_capture_dirs()
        if writable:
            return writable[0]
        return self.capture_dir

    def _dumpcap_privilege_hint(self, interface: str, detail: str) -> str:
        return (
            f"{detail} Packet capture on {interface} requires dumpcap write access and capture privileges. "
            "Run scripts/fix_project_permissions_and_dependencies.sh to repair project permissions, "
            "dumpcap capabilities, and writable capture directories."
        )

    def _run(self, cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if (
            result.returncode != 0
            and self.passwordless_sudo
            and self.sudo_path
            and cmd
            and cmd[0] == self.iw_path
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

    def _set_channel(self, interface: str, channel: int) -> Dict[str, Any]:
        if not self.iw_path:
            return {"ok": False, "error": "iw not installed"}
        result = self._run([self.iw_path, "dev", interface, "set", "channel", str(channel), "HT20"], timeout=8)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "Channel set failed").strip()
            lowered = detail.lower()
            if "operation not permitted" in lowered or "permission denied" in lowered:
                detail = (
                    f"{detail} The host denied channel control on {interface}. "
                    "Grant CAP_NET_ADMIN/root privileges to the backend process or pre-configure the interface for controlled monitor-mode scanning."
                )
            return {"ok": False, "error": detail}
        return {"ok": True}

    def _run_dumpcap(self, command: List[str], capture_seconds: float) -> subprocess.CompletedProcess[str]:
        return self._run(command, timeout=max(10, int(capture_seconds) + 8))

    def _run_tcpdump(self, command: List[str], capture_seconds: float) -> subprocess.CompletedProcess[str]:
        return self._run(command, timeout=max(10, int(math.ceil(capture_seconds)) + 8))

    def _capture_with_tcpdump(self, interface: str, pcap_path: Path, capture_seconds: float) -> Dict[str, Any]:
        if not self.tcpdump_path:
            return {"ok": False, "error": "tcpdump not installed", "pcap_path": str(pcap_path)}
        # tcpdump on this host needs a longer dwell than dumpcap to emit usable monitor-mode frames.
        effective_seconds = max(2.0, float(capture_seconds))
        seconds = max(1, int(math.ceil(effective_seconds)))
        command = [
            self.tcpdump_path,
            "-i",
            interface,
            "-U",
            "-G",
            str(seconds),
            "-W",
            "1",
            "-w",
            str(pcap_path),
        ]
        if os.geteuid() == 0:
            command[1:1] = ["-Z", "root"]
        result = self._run_tcpdump(command, effective_seconds)
        detail = (result.stderr or result.stdout or "").strip()
        if result.returncode == 0 and pcap_path.exists():
            return {"ok": True, "pcap_path": str(pcap_path)}
        return {
            "ok": False,
            "error": detail or "tcpdump capture failed",
            "pcap_path": str(pcap_path),
        }

    def _capture_pcap(self, interface: str, channel: int, dwell_ms: int) -> Dict[str, Any]:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        capture_seconds = max(1.0, float(dwell_ms) / 1000.0)
        candidate_dirs = self._writable_capture_dirs()
        if not candidate_dirs:
            return {
                "ok": False,
                "error": self._dumpcap_privilege_hint(
                    interface,
                    "No writable capture directory is available under logs/wifi_mk7 or /tmp/ghostrecon_wifi_mk7.",
                ),
                "pcap_path": "",
            }
        last_detail = "Capture failed"
        last_path = ""

        for capture_dir in candidate_dirs:
            dumpcap_path = capture_dir / f"wifi_mk7_ch{channel}_{timestamp}.pcapng"
            tcpdump_path = capture_dir / f"wifi_mk7_ch{channel}_{timestamp}.pcap"
            detail = "Capture failed"
            lowered = ""
            last_path = str(dumpcap_path)

            if self.dumpcap_path:
                command = [
                    self.dumpcap_path,
                    "-B",
                    "32",
                    "-i",
                    interface,
                    "-a",
                    f"duration:{capture_seconds:.2f}",
                    "-w",
                    str(dumpcap_path),
                ]

                if not interface.endswith("mon"):
                    command.insert(1, "-I")

                result = self._run_dumpcap(command, capture_seconds)
                detail = (result.stderr or result.stdout or "Capture failed").strip()
                lowered = detail.lower()
                last_detail = detail

                if result.returncode != 0 and interface.endswith("mon") and "monitor mode" in lowered:
                    retry_result = self._run_dumpcap(
                        [
                            self.dumpcap_path,
                            "-i",
                            interface,
                            "-a",
                            f"duration:{capture_seconds:.2f}",
                            "-w",
                            str(dumpcap_path),
                        ],
                        capture_seconds,
                    )
                    result = retry_result
                    detail = (result.stderr or result.stdout or "Capture failed").strip()
                    lowered = detail.lower()
                    last_detail = detail

                if result.returncode == 0:
                    return {"ok": True, "pcap_path": str(dumpcap_path)}

            if self.tcpdump_path and ("permission denied" in lowered or "operation not permitted" in lowered or "could not be opened" in lowered):
                fallback = self._capture_with_tcpdump(interface, tcpdump_path, capture_seconds)
                last_path = str(tcpdump_path)
                if fallback.get("ok"):
                    return fallback
                detail = str(fallback.get("error") or detail).strip()
                lowered = detail.lower()
                last_detail = detail

            if ("permission denied" in lowered or "operation not permitted" in lowered) and capture_dir != self.fallback_capture_dir:
                continue

            break

        lowered = last_detail.lower()
        if "permission denied" in lowered or "operation not permitted" in lowered:
            last_detail = self._dumpcap_privilege_hint(interface, last_detail)
        return {"ok": False, "error": last_detail, "pcap_path": last_path}

    def _parse_pcap(self, pcap_path: str) -> Dict[str, Any]:
        result = self._run(
            [
                self.tshark_path,
                "-r",
                pcap_path,
                "-Y",
                "wlan",
                "-T",
                "fields",
                "-E",
                "header=n",
                "-E",
                "separator=\t",
                "-e",
                "frame.number",
                "-e",
                "frame.time_epoch",
                "-e",
                "wlan.fc.type_subtype",
                "-e",
                "wlan.ta",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.da",
                "-e",
                "wlan.ra",
                "-e",
                "wlan.bssid",
                "-e",
                "wlan.ssid",
                "-e",
                "radiotap.dbm_antsignal",
                "-e",
                "wlan_radio.channel",
                "-e",
                "wlan_radio.frequency",
                "-e",
                "wlan.fixed.capabilities.privacy",
                "-e",
                "wlan.rsn.akms.type",
                "-e",
                "wlan.rsn.pcs.type",
                "-e",
                "wlan.rsn.capabilities.mfpr",
                "-e",
                "wlan.rsn.capabilities.mfpc",
                "-e",
                "wps.manufacturer",
                "-e",
                "wps.model_name",
                "-e",
                "wps.device_name",
                "-e",
                "wlan.supported_rates",
                "-e",
                "wlan.extended_supported_rates",
                "-e",
                "frame.len",
                "-e",
                "wlan.fc.type",
                "-e",
                "wlan.fc.retry",
                "-e",
                "wlan.seq",
                "-e",
                "wlan.qos.priority",
                "-e",
                "radiotap.datarate",
                "-e",
                "wlan.ht.capabilities",
                "-e",
                "wlan.vht.capabilities",
                "-e",
                "wlan.htc.he",
                "-e",
                "wps.model_number",
                "-e",
                "wps.serial_number",
                "-e",
                "wps.config_methods",
                "-e",
                "wps.rf_bands",
                "-e",
                "wps.primary_device_type.subcategory_camera",
                "-e",
                "dhcp.option.hostname",
                "-e",
                "eapol.type",
                "-e",
                "eapol.keydes.type",
                "-e",
                "eapol.keydes.key_len",
                "-e",
                "eapol.keydes.replay_counter",
                "-e",
                "wlan_rsna_eapol.keydes.msgnr",
                "-e",
                "wlan_rsna_eapol.keydes.key_info",
                "-e",
                "wlan_rsna_eapol.keydes.key_info.key_ack",
                "-e",
                "wlan_rsna_eapol.keydes.key_info.key_mic",
                "-e",
                "wlan_rsna_eapol.keydes.key_info.secure",
                "-e",
                "wlan_rsna_eapol.keydes.key_info.install",
                "-e",
                "wlan_rsna_eapol.keydes.key_info.request",
                "-e",
                "wlan_rsna_eapol.keydes.key_info.encrypted_key_data",
                "-e",
                "wlan_rsna_eapol.keydes.data_len",
            ],
            timeout=20,
        )
        if result.returncode != 0:
            return {"ok": False, "error": (result.stderr or result.stdout or "tshark parse failed").strip(), "frames": []}
        frames = self.parser.parse_lines((result.stdout or "").splitlines())
        return {"ok": True, "frames": frames}

    def parse_capture_file(self, pcap_path: str) -> Dict[str, Any]:
        if not self.tshark_path:
            return {"ok": False, "error": "tshark unavailable", "frames": []}
        return self._parse_pcap(pcap_path)

    def capture_channel(self, interface: str, channel: int, dwell_ms: int) -> Dict[str, Any]:
        if not self.available():
            return {"ok": False, "error": "WiFi capture tooling is unavailable on this host."}

        channel_result = self._set_channel(interface, channel)
        if not channel_result.get("ok"):
            return {"ok": False, "error": channel_result.get("error"), "channel": channel}

        capture_result = self._capture_pcap(interface, channel, dwell_ms)
        if not capture_result.get("ok"):
            return {"ok": False, "error": capture_result.get("error"), "channel": channel, "pcap_path": capture_result.get("pcap_path")}

        parse_result = self._parse_pcap(capture_result["pcap_path"])
        if not parse_result.get("ok"):
            return {
                "ok": False,
                "error": parse_result.get("error"),
                "channel": channel,
                "pcap_path": capture_result["pcap_path"],
                "frames": [],
            }

        return {
            "ok": True,
            "channel": channel,
            "pcap_path": capture_result["pcap_path"],
            "frame_count": len(parse_result.get("frames", [])),
            "frames": parse_result.get("frames", []),
        }
