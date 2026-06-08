from __future__ import annotations

import json
import subprocess
import threading
import time
from collections import deque
from shutil import which
from typing import Any, Dict, List, Optional


class RTL433Manager:
    BENIGN_LOG_MARKERS = (
        "signal caught, exiting!",
    )
    def __init__(self) -> None:
        self.binary = which("rtl_433")
        self.device_query = ""
        self.process: Optional[subprocess.Popen[str]] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.sweep_thread: Optional[threading.Thread] = None
        self.events: deque[Dict[str, Any]] = deque(maxlen=200)
        self.logs: deque[str] = deque(maxlen=40)
        self.freq_mhz: Optional[float] = None
        self.started_at: Optional[float] = None
        self.last_event_at: Optional[float] = None
        self.last_error: str = ""
        self.last_exit_code: Optional[int] = None
        self.mode: str = "idle"
        self.sweep_frequencies: List[float] = []
        self.dwell_seconds: float = 4.0
        self.current_index: int = 0
        self.cycle_count: int = 0
        self.completed: bool = False
        self.completed_at: Optional[float] = None
        self.attempted_frequencies: List[float] = []
        self._lock = threading.RLock()
        self._stop_event = threading.Event()

    def is_installed(self) -> bool:
        return bool(self.binary)

    def start(self, freq_mhz: float) -> Dict[str, Any]:
        with self._lock:
            if not self.binary:
                return {"status": "unavailable", "error": "rtl_433 is not installed on this host."}

            if self.process and self.process.poll() is None:
                if self.freq_mhz == freq_mhz:
                    return {"status": "already_running", "freq_mhz": self.freq_mhz}
                self.stop()

            cmd = [
                self.binary,
                "-d",
                self.device_query,
                "-M",
                "level",
                "-M",
                "time:iso",
                "-F",
                "log",
                "-F",
                "json",
                "-f",
                f"{freq_mhz}M",
            ]

            self.last_error = ""
            self.last_exit_code = None
            self.freq_mhz = float(freq_mhz)
            self.mode = "single"
            self.current_index = 1
            self.cycle_count = 1
            self.completed = False
            self.completed_at = None

            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                self.started_at = time.time()
                self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
                self.reader_thread.start()
                return {"status": "started", "freq_mhz": self.freq_mhz}
            except Exception as exc:
                self.process = None
                self.last_error = str(exc)
                return {"status": "failed", "error": str(exc)}

    def start_sweep(self, frequencies_mhz: List[float], dwell_seconds: float = 4.0) -> Dict[str, Any]:
        with self._lock:
            if not self.binary:
                return {"status": "unavailable", "error": "rtl_433 is not installed on this host."}

            cleaned = [float(freq) for freq in frequencies_mhz if freq]
            if not cleaned:
                return {"status": "invalid", "error": "No decode frequencies were provided."}

            self.stop()
            self.events.clear()
            self.logs.clear()
            self.last_error = ""
            self.last_exit_code = None
            self.mode = "sweep"
            self.sweep_frequencies = cleaned
            self.dwell_seconds = float(dwell_seconds or 4.0)
            self.current_index = 0
            self.cycle_count = 0
            self.started_at = time.time()
            self.completed = False
            self.completed_at = None
            self.attempted_frequencies = []
            self._stop_event.clear()

            self.sweep_thread = threading.Thread(target=self._sweep_loop, daemon=True)
            self.sweep_thread.start()
            return {
                "status": "started",
                "mode": "sweep",
                "frequencies_mhz": self.sweep_frequencies,
                "dwell_seconds": self.dwell_seconds,
            }

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop_event.set()
            if not self.process:
                self.mode = "idle"
                return {"status": "idle"}
            self._stop_process_locked()
            self.mode = "idle"
            return {"status": "stopped", "exit_code": self.last_exit_code}

    def _stop_process_locked(self) -> None:
        if not self.process:
            return
        try:
            self.process.terminate()
            self.process.wait(timeout=3)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass
        self.last_exit_code = self.process.poll()
        self.process = None

    def _launch_process_locked(self, freq_mhz: float) -> Dict[str, Any]:
        cmd = [
            self.binary,
            "-d",
            self.device_query,
            "-M",
            "level",
            "-M",
            "time:iso",
            "-F",
            "log",
            "-F",
            "json",
            "-f",
            f"{freq_mhz}M",
        ]

        self.freq_mhz = float(freq_mhz)
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        return {"status": "started", "freq_mhz": self.freq_mhz}

    def _sweep_loop(self) -> None:
        self.cycle_count = 1
        for index, freq_mhz in enumerate(self.sweep_frequencies):
            if self._stop_event.is_set():
                break
            with self._lock:
                self.current_index = index + 1
                self.attempted_frequencies.append(float(freq_mhz))
                try:
                    self._launch_process_locked(freq_mhz)
                except Exception as exc:
                    self.last_error = str(exc)
                    self.logs.append(self.last_error)
                    continue
            sleep_until = time.time() + self.dwell_seconds
            while time.time() < sleep_until:
                if self._stop_event.is_set():
                    break
                time.sleep(0.2)
            with self._lock:
                self._stop_process_locked()
        with self._lock:
            self.mode = "idle"
            self.completed = not self._stop_event.is_set()
            self.completed_at = time.time()

    def _reader_loop(self) -> None:
        process = self.process
        if not process:
            return

        stdout = process.stdout
        stderr = process.stderr

        def consume_stderr() -> None:
            if not stderr:
                return
            for line in stderr:
                cleaned = (line or "").replace("\x00", " ").strip()
                if not cleaned:
                    continue
                self.logs.append(cleaned)
                if cleaned.lower() not in self.BENIGN_LOG_MARKERS:
                    self.last_error = cleaned

        stderr_thread = threading.Thread(target=consume_stderr, daemon=True)
        stderr_thread.start()

        if stdout:
            for line in stdout:
                cleaned = (line or "").strip()
                if not cleaned:
                    continue
                try:
                    payload = json.loads(cleaned)
                    payload["_ingested_at"] = time.time()
                    payload["_rtl433_freq_mhz"] = self.freq_mhz
                    self.events.appendleft(payload)
                    self.last_event_at = payload["_ingested_at"]
                except Exception:
                    self.logs.append(cleaned)

        try:
            self.last_exit_code = process.wait(timeout=1)
        except Exception:
            self.last_exit_code = process.poll()

    def get_state(self) -> Dict[str, Any]:
        running = bool(self.process and self.process.poll() is None)
        products: Dict[str, int] = {}
        brands: Dict[str, int] = {}
        frequencies: Dict[str, int] = {}
        for event in self.events:
            product_key = str(event.get("model") or event.get("type") or event.get("protocol") or "Unknown Device")
            products[product_key] = products.get(product_key, 0) + 1
            if event.get("brand"):
                brand_key = str(event["brand"])
                brands[brand_key] = brands.get(brand_key, 0) + 1
            if event.get("_rtl433_freq_mhz") is not None:
                freq_key = f"{float(event['_rtl433_freq_mhz']):.3f}"
                frequencies[freq_key] = frequencies.get(freq_key, 0) + 1
        status_detail = "idle"
        if running:
            status_detail = "decoding"
        elif self.completed and self.events:
            status_detail = "completed_with_events"
        elif self.completed and self.last_exit_code not in (None, 0, 124):
            status_detail = "completed_with_backend_error"
        elif self.completed:
            status_detail = "completed_no_events"
        return {
            "installed": self.is_installed(),
            "binary": self.binary,
            "device_query": self.device_query,
            "running": running,
            "mode": self.mode,
            "freq_mhz": self.freq_mhz,
            "started_at": self.started_at,
            "last_event_at": self.last_event_at,
            "event_count": len(self.events),
            "last_error": self.last_error,
            "last_exit_code": self.last_exit_code,
            "sweep_frequencies": self.sweep_frequencies,
            "dwell_seconds": self.dwell_seconds,
            "current_index": self.current_index,
            "cycle_count": self.cycle_count,
            "completed": self.completed,
            "completed_at": self.completed_at,
            "attempted_frequencies": self.attempted_frequencies,
            "status_detail": status_detail,
            "top_products": sorted(products.items(), key=lambda item: item[1], reverse=True)[:8],
            "top_brands": sorted(brands.items(), key=lambda item: item[1], reverse=True)[:8],
            "frequency_hits": sorted(frequencies.items(), key=lambda item: item[0]),
            "recent_events": list(self.events)[:25],
            "recent_logs": list(self.logs)[:20],
        }
