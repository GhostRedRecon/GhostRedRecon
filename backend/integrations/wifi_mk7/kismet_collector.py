from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from shutil import which
from typing import Any, Dict, List


class KismetCollector:
    def __init__(self, root_dir: Path) -> None:
        self.binary = which("kismet") or self._fallback("/usr/bin/kismet")
        self.dump_binary = which("kismetdb_dump_devices") or self._fallback("/usr/bin/kismetdb_dump_devices")
        self.base_dir = root_dir / "logs" / "wifi_mk7" / "pipeline" / "kismet"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.process: subprocess.Popen[str] | None = None
        self.session_dir: Path | None = None
        self.log_path: Path | None = None
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.interfaces: List[str] = []
        self.last_stop_state = "idle"

    @staticmethod
    def _fallback(path: str) -> str | None:
        return path if Path(path).exists() else None

    def available(self) -> bool:
        return bool(self.binary and self.dump_binary)

    def start(self, interfaces: List[str]) -> Dict[str, Any]:
        if not self.available():
            return {"ok": False, "error": "kismet or kismetdb_dump_devices not installed"}
        if self.process and self.process.poll() is None:
            return {"ok": True, "status": "already_running", "session_dir": str(self.session_dir or "")}
        selected = [item for item in interfaces if item]
        if not selected:
            return {"ok": False, "error": "No monitor interface available for kismet"}

        stamp = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.base_dir / stamp
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.session_dir / "kismet.log"
        self.interfaces = selected
        self.stopped_at = None
        self.last_stop_state = "starting"

        command = [
            self.binary,
            "--no-ncurses",
            "--silent",
            "-T",
            "kismetdb",
            "-p",
            str(self.session_dir),
            "-t",
            f"wifi_mk7_{stamp}",
        ]
        for interface in selected:
            command.extend(["-c", interface])

        log_handle = self.log_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            command,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        self.started_at = time.time()
        self.last_stop_state = "running"
        return {"ok": True, "status": "started", "session_dir": str(self.session_dir)}

    def stop(self) -> None:
        if not self.process:
            return
        try:
            if self.process.poll() is None:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                    self.last_stop_state = "terminated_process_group"
                except Exception:
                    self.process.terminate()
                    self.last_stop_state = "terminated_process"
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                        self.last_stop_state = "killed_process_group"
                    except Exception:
                        self.process.kill()
                        self.last_stop_state = "killed_process"
                    self.process.wait(timeout=2)
        finally:
            self.stopped_at = time.time()
        self.process = None

    def clear(self) -> None:
        self.stop()
        self.session_dir = None
        self.log_path = None
        self.started_at = None
        self.stopped_at = None
        self.interfaces = []
        self.last_stop_state = "idle"

    def status(self) -> Dict[str, Any]:
        active = bool(self.process and self.process.poll() is None)
        return {
            "name": "kismet",
            "available": self.available(),
            "path": self.binary or "",
            "active": active,
            "pid": int(self.process.pid) if self.process and active else None,
            "interfaces": self.interfaces,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_stop_state": self.last_stop_state,
            "session_dir": str(self.session_dir) if self.session_dir else "",
            "kismetdb_path": str(self.latest_kismetdb()) if self.latest_kismetdb() else "",
            "role": "device intelligence",
        }

    def latest_kismetdb(self) -> Path | None:
        if not self.session_dir or not self.session_dir.exists():
            return None
        candidates = sorted(self.session_dir.glob("*.kismetdb"))
        return candidates[-1] if candidates else None

    def snapshot(self) -> Dict[str, Any]:
        db_path = self.latest_kismetdb()
        if not db_path or not db_path.exists():
            return {"devices": [], "source": "kismet", "kismetdb_path": str(db_path or "")}
        output_path = self.session_dir / "devices.ekjson"
        result = subprocess.run(
            [self.dump_binary, "-i", str(db_path), "-o", str(output_path), "-f", "-e", "-j"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if result.returncode != 0 or not output_path.exists():
            return {
                "devices": [],
                "source": "kismet",
                "kismetdb_path": str(db_path),
                "error": (result.stderr or result.stdout or "kismetdb dump failed").strip(),
            }
        devices: List[Dict[str, Any]] = []
        with output_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except Exception:
                    continue
                devices.append(
                    {
                        "mac": str(
                            raw.get("kismet_device_base_macaddr")
                            or raw.get("dot11_device_last_bssid")
                            or raw.get("kismet.device.base.macaddr")
                            or ""
                        ).lower(),
                        "name": raw.get("kismet_device_base_name") or raw.get("kismet.device.base.name") or "",
                        "type": raw.get("kismet_device_base_type") or raw.get("kismet.device.base.type") or "",
                        "phy": raw.get("kismet_device_base_phyname") or raw.get("kismet.device.base.phyname") or "",
                        "channel": raw.get("kismet_device_base_channel") or raw.get("kismet.device.base.channel") or "",
                        "signal": raw.get("kismet_device_base_signal_kismet_common_signal_last_signal")
                        or raw.get("kismet.device.base.signal.kismet.common.signal.last_signal")
                        or "",
                        "manuf": raw.get("kismet_device_base_manuf") or raw.get("kismet.device.base.manuf") or "",
                    }
                )
        return {"devices": devices, "source": "kismet", "kismetdb_path": str(db_path)}
