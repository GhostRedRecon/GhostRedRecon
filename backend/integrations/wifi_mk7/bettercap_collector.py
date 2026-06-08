from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from pathlib import Path
from shutil import which
from typing import Any, Dict, List


MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")


class BettercapCollector:
    def __init__(self, root_dir: Path) -> None:
        self.binary = which("bettercap") or self._fallback("/usr/bin/bettercap")
        self.base_dir = root_dir / "logs" / "wifi_mk7" / "pipeline" / "bettercap"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.process: subprocess.Popen[str] | None = None
        self.session_dir: Path | None = None
        self.log_path: Path | None = None
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.interface = ""
        self.last_stop_state = "idle"

    @staticmethod
    def _fallback(path: str) -> str | None:
        return path if Path(path).exists() else None

    def available(self) -> bool:
        return bool(self.binary)

    def start(self, interface: str) -> Dict[str, Any]:
        if not self.available():
            return {"ok": False, "error": "bettercap not installed"}
        if self.process and self.process.poll() is None:
            return {"ok": True, "status": "already_running", "session_dir": str(self.session_dir or "")}
        if not interface:
            return {"ok": False, "error": "No monitor interface available for bettercap"}

        stamp = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.base_dir / stamp
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.session_dir / "bettercap.log"
        self.interface = interface
        self.stopped_at = None
        self.last_stop_state = "starting"
        command = [
            self.binary,
            "-iface",
            interface,
            "-no-colors",
            "-silent",
            "-eval",
            "set wifi.handshakes false; wifi.recon on; events.stream on",
        ]
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
        self.interface = ""
        self.last_stop_state = "idle"

    def status(self) -> Dict[str, Any]:
        active = bool(self.process and self.process.poll() is None)
        return {
            "name": "bettercap",
            "available": self.available(),
            "path": self.binary or "",
            "active": active,
            "pid": int(self.process.pid) if self.process and active else None,
            "interfaces": [self.interface] if self.interface else [],
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_stop_state": self.last_stop_state,
            "session_dir": str(self.session_dir) if self.session_dir else "",
            "log_path": str(self.log_path) if self.log_path else "",
            "role": "live recon/events",
        }

    def snapshot(self) -> Dict[str, Any]:
        if not self.log_path or not self.log_path.exists():
            return {"events": [], "source": "bettercap", "log_path": str(self.log_path or "")}
        events = []
        lines = self.log_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-300:]
        for line in lines:
            text = line.strip()
            if not text:
                continue
            macs = [match.group(0).lower() for match in MAC_RE.finditer(text)]
            if not macs:
                continue
            lowered = text.lower()
            events.append(
                {
                    "macs": macs,
                    "text": text,
                    "camera_hint": any(keyword in lowered for keyword in ("camera", "rtsp", "onvif", "tuya", "hik", "ezviz", "ring", "nest", "arlo", "reolink")),
                }
            )
        return {"events": events, "source": "bettercap", "log_path": str(self.log_path)}
