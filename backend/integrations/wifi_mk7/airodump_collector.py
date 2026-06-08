from __future__ import annotations

import csv
import os
import signal
import subprocess
import time
from pathlib import Path
from shutil import which
from typing import Any, Dict, List


class AirodumpCollector:
    def __init__(self, root_dir: Path) -> None:
        self.binary = which("airodump-ng") or self._fallback("/usr/sbin/airodump-ng")
        self.base_dir = root_dir / "logs" / "wifi_mk7" / "pipeline" / "airodump"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.process: subprocess.Popen[str] | None = None
        self.session_dir: Path | None = None
        self.output_prefix: Path | None = None
        self.log_path: Path | None = None
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.interfaces: List[str] = []
        self.last_stop_state = "idle"

    @staticmethod
    def _fallback(path: str) -> str | None:
        return path if Path(path).exists() else None

    def available(self) -> bool:
        return bool(self.binary)

    def start(self, interfaces: List[str], bands: List[str] | None = None, write_interval_seconds: int = 1) -> Dict[str, Any]:
        if not self.available():
            return {"ok": False, "error": "airodump-ng not installed"}
        if self.process and self.process.poll() is None:
            return {"ok": True, "status": "already_running", "session_dir": str(self.session_dir or "")}
        selected = [item for item in interfaces if item]
        if not selected:
            return {"ok": False, "error": "No monitor interface available for airodump-ng"}

        stamp = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.base_dir / stamp
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.output_prefix = self.session_dir / "capture"
        self.log_path = self.session_dir / "airodump.log"
        self.interfaces = selected
        self.stopped_at = None
        self.last_stop_state = "starting"

        command = [
            self.binary,
            "--write",
            str(self.output_prefix),
            "--output-format",
            "csv",
            "--write-interval",
            str(max(1, int(write_interval_seconds or 1))),
            "--manufacturer",
            "--wps",
            "--background",
            "1",
            ",".join(selected),
        ]
        band_set = {str(item).lower() for item in (bands or [])}
        if band_set == {"2.4ghz"}:
            command[1:1] = ["--band", "bg"]
        elif band_set == {"5ghz"}:
            command[1:1] = ["--band", "a"]
        else:
            command[1:1] = ["--band", "abg"]

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
        self.output_prefix = None
        self.log_path = None
        self.started_at = None
        self.stopped_at = None
        self.interfaces = []
        self.last_stop_state = "idle"

    def status(self) -> Dict[str, Any]:
        active = bool(self.process and self.process.poll() is None)
        return {
            "name": "airodump-ng",
            "available": self.available(),
            "path": self.binary or "",
            "active": active,
            "pid": int(self.process.pid) if self.process and active else None,
            "interfaces": self.interfaces,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_stop_state": self.last_stop_state,
            "session_dir": str(self.session_dir) if self.session_dir else "",
            "csv_path": str(self.csv_path()) if self.csv_path() else "",
            "role": "RF scanner",
        }

    def csv_path(self) -> Path | None:
        if not self.output_prefix:
            return None
        candidates = sorted(self.session_dir.glob("capture*.csv")) if self.session_dir else []
        if candidates:
            return candidates[-1]
        fallback = Path(f"{self.output_prefix}-01.csv")
        return fallback if fallback.exists() else None

    def snapshot(self) -> Dict[str, Any]:
        path = self.csv_path()
        if not path or not path.exists():
            return {"aps": [], "stations": [], "source": "airodump-ng", "csv_path": str(path or "")}

        aps: List[Dict[str, Any]] = []
        stations: List[Dict[str, Any]] = []
        mode = "aps"
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if not row:
                    continue
                head = row[0].strip().lower()
                if head == "station mac":
                    mode = "stations"
                    continue
                if head == "bssid" or head.startswith("#"):
                    continue
                if mode == "aps":
                    aps.append(
                        {
                            "bssid": row[0].strip().lower() if len(row) > 0 else "",
                            "channel": row[3].strip() if len(row) > 3 else "",
                            "privacy": row[5].strip() if len(row) > 5 else "",
                            "power": row[8].strip() if len(row) > 8 else "",
                            "beacons": row[9].strip() if len(row) > 9 else "",
                            "ivs": row[10].strip() if len(row) > 10 else "",
                            "lan_ip": row[11].strip() if len(row) > 11 else "",
                            "essid": row[13].strip() if len(row) > 13 else "",
                            "manufacturer": row[14].strip() if len(row) > 14 else "",
                            "wps": row[15].strip() if len(row) > 15 else "",
                        }
                    )
                else:
                    stations.append(
                        {
                            "mac": row[0].strip().lower() if len(row) > 0 else "",
                            "first_seen": row[1].strip() if len(row) > 1 else "",
                            "last_seen": row[2].strip() if len(row) > 2 else "",
                            "power": row[3].strip() if len(row) > 3 else "",
                            "packets": row[4].strip() if len(row) > 4 else "",
                            "bssid": row[5].strip().lower() if len(row) > 5 else "",
                            "probed_essids": ",".join(col.strip() for col in row[6:] if col.strip()),
                        }
                    )
        return {"aps": aps, "stations": stations, "source": "airodump-ng", "csv_path": str(path)}
