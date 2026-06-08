# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/sdr/sdr_controller.py
# VERSION:      v7.0.0 (PRODUCTION - SIGINT SDR CONTROL PLANE)
# UPDATED:      2026-03-19
# =============================================================================

import subprocess
import time
import os
import signal
import re
from collections import deque

from backend.config.project_config import get_project_config


class SDRController:
    """
    SDR Controller (HackRF)

    Architecture Role:
    ------------------
    Hardware abstraction layer between GhostRecon runtime and HackRF.

    Responsibilities:
    -----------------
    - Control hackrf_transfer lifecycle
    - Tune / retune frequency
    - Ensure IQ stream availability
    - Provide health + state for pipeline

    Design Principles:
    ------------------
    - Idempotent operations (safe repeated calls)
    - Fail-fast validation (IQ must exist)
    - Process isolation (no zombie SDR processes)
    - Runtime-compatible interface

    Required Interface:
    -------------------
    start(freq_mhz)
    set_frequency(freq_mhz)
    stop()
    get_state()
    is_healthy()
    """

    def __init__(
        self,
        iq_path=None,
        sample_rate=None,
        startup_timeout=None,
        amp_enable=None,
        lna_gain=None,
        vga_gain=None,
    ):
        config = get_project_config().get("sdr", {})
        runtime_config = config.get("runtime", {})
        rf_config = config.get("rf", {})

        self.iq_path = iq_path or runtime_config.get("iqPath", "/dev/shm/ghostrecon_iq.iq")
        self.default_sample_rate = int(sample_rate or runtime_config.get("sampleRate", 10_000_000))
        self.sample_rate = self.default_sample_rate
        self.startup_timeout = float(startup_timeout or runtime_config.get("startupTimeoutSeconds", 3))
        self.default_amp_enable = rf_config.get("ampEnable") if amp_enable is None else amp_enable
        self.default_lna_gain = int(rf_config.get("lnaGain", 24) if lna_gain is None else lna_gain)
        self.default_vga_gain = int(rf_config.get("vgaGain", 32) if vga_gain is None else vga_gain)
        self.amp_enable = self.default_amp_enable
        self.lna_gain = self.default_lna_gain
        self.vga_gain = self.default_vga_gain
        self.active_profile_id = "default"
        self.active_profile_label = "Default SDR"
        self.active_profile_reason = "config_default"

        self.process = None
        self.running = False
        self.freq_mhz = None
        self.stderr_path = f"{self.iq_path}.stderr.log"
        self.last_error = ""
        self.last_exit_code = None
        self.last_start_attempt_at = None
        self.last_started_at = None
        self.last_stderr_excerpt = ""
        self.event_history = deque(maxlen=20)

    @staticmethod
    def _normalize_hackrf_lna_gain(value: int) -> int:
        value = max(0, min(40, int(value)))
        return int(round(value / 8.0) * 8)

    @staticmethod
    def _normalize_hackrf_vga_gain(value: int) -> int:
        value = max(0, min(62, int(value)))
        return int(round(value / 2.0) * 2)

    # =========================================================================
    # START / RETUNE (CORE ENTRYPOINT)
    # =========================================================================
    def start(self, freq_mhz: float) -> dict:
        """
        Start or retune SDR
        """

        freq_hz = int(freq_mhz * 1e6)

        print(f"\n📡 ================= SDR START =================")
        print(f"📡 [SDR] Target Frequency → {freq_mhz} MHz")
        self.last_start_attempt_at = time.time()
        self.last_error = ""
        self.last_exit_code = None
        self._truncate_stderr_log()

        # Always stop existing process (retune-safe)
        self.stop()

        cmd = [
            "hackrf_transfer",
            "-r", self.iq_path,
            "-f", str(freq_hz),
            "-s", str(self.sample_rate),
            "-l", str(self.lna_gain),
            "-g", str(self.vga_gain),
        ]

        if self.amp_enable:
            cmd.append("-a")
            cmd.append("1")

        try:
            stderr_handle = open(self.stderr_path, "wb")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
            )
            stderr_handle.close()

            # Wait for IQ data
            if not self._wait_for_iq_data(timeout=self.startup_timeout):
                self._refresh_process_telemetry()
                stderr_excerpt = self._read_stderr_excerpt()
                detail = stderr_excerpt or "IQ stream not producing data"
                raise RuntimeError(detail)

            self.running = True
            self.freq_mhz = freq_mhz
            self.last_started_at = time.time()
            self.last_stderr_excerpt = self._read_stderr_excerpt()
            self._record_event("start_ok", freq_mhz=freq_mhz)

            print("✅ [SDR] RUNNING")
            print("================================================\n")

            return {
                "status": "started",
                "freq_mhz": freq_mhz,
                "profile_id": self.active_profile_id,
            }

        except Exception as e:
            print(f"🔥 [SDR] START FAILED → {e}")
            self.last_error = str(e)
            self.last_stderr_excerpt = self._read_stderr_excerpt()
            self._record_event("start_failed", freq_mhz=freq_mhz, error=self.last_error)
            self._cleanup()

            return {
                "status": "failed",
                "error": str(e),
            }

    # =========================================================================
    # SET FREQUENCY (RUNTIME CONTRACT)
    # =========================================================================
    def set_frequency(self, freq_mhz: float) -> dict:
        """
        Runtime-compatible retune method

        HackRF limitation:
        - No live retune → must restart process
        """

        print(f"\n🔄 ================= SDR RETUNE =================")
        print(f"📡 [SDR] Retuning → {freq_mhz} MHz")

        return self.start(freq_mhz)

    # =========================================================================
    # STOP
    # =========================================================================
    def stop(self):
        """
        Stop SDR safely (idempotent)
        """

        if not self.process:
            return

        print("🛑 [SDR] Stopping")

        try:
            self.process.terminate()
            self.process.wait(timeout=2)
        except Exception:
            try:
                os.kill(self.process.pid, signal.SIGKILL)
            except Exception:
                pass

        self._refresh_process_telemetry()
        self._record_event("stop", freq_mhz=self.freq_mhz, exit_code=self.last_exit_code)

        self._cleanup()

    # =========================================================================
    # INTERNAL CLEANUP
    # =========================================================================
    def _cleanup(self):
        self.process = None
        self.running = False

    # =========================================================================
    # IQ VALIDATION
    # =========================================================================
    def _wait_for_iq_data(self, timeout=3) -> bool:
        """
        Wait for IQ file to receive data
        """

        start = time.time()

        while time.time() - start < timeout:

            if os.path.exists(self.iq_path):
                size = os.path.getsize(self.iq_path)

                if size > 0:
                    print(f"📡 [SDR] IQ STREAM OK → {size} bytes")
                    return True

            time.sleep(0.2)

        return False

    def _truncate_stderr_log(self):
        try:
            with open(self.stderr_path, "wb"):
                pass
        except Exception:
            pass

    def _read_stderr_excerpt(self, limit=800) -> str:
        try:
            if not os.path.exists(self.stderr_path):
                return ""
            with open(self.stderr_path, "rb") as handle:
                data = handle.read(limit)
            text = data.decode("utf-8", errors="ignore")
            text = text.replace("\x00", " ")
            text = re.sub(r"\s+", " ", text).strip()
            if not text:
                return ""
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            return " | ".join(lines[-3:])
        except Exception:
            return ""

    def _refresh_process_telemetry(self):
        if not self.process:
            return
        try:
            code = self.process.poll()
            if code is not None:
                self.last_exit_code = code
                excerpt = self._read_stderr_excerpt()
                self.last_stderr_excerpt = excerpt
                if excerpt:
                    self.last_error = excerpt
        except Exception:
            pass

    def _record_event(self, kind, **detail):
        self.event_history.appendleft({
            "timestamp": time.time(),
            "kind": kind,
            **detail,
        })

    def configure_runtime(
        self,
        sample_rate=None,
        amp_enable=None,
        lna_gain=None,
        vga_gain=None,
        profile_id: str | None = None,
        profile_label: str | None = None,
        profile_reason: str | None = None,
    ) -> None:
        self.sample_rate = int(self.default_sample_rate if sample_rate is None else sample_rate)
        self.amp_enable = self.default_amp_enable if amp_enable is None else bool(amp_enable)
        requested_lna = self.default_lna_gain if lna_gain is None else lna_gain
        requested_vga = self.default_vga_gain if vga_gain is None else vga_gain
        self.lna_gain = self._normalize_hackrf_lna_gain(requested_lna)
        self.vga_gain = self._normalize_hackrf_vga_gain(requested_vga)
        self.active_profile_id = profile_id or "default"
        self.active_profile_label = profile_label or "Default SDR"
        self.active_profile_reason = profile_reason or "runtime_override"
        self._record_event(
            "profile",
            profile_id=self.active_profile_id,
            sample_rate=self.sample_rate,
            amp_enable=self.amp_enable,
            requested_lna_gain=int(requested_lna),
            lna_gain=self.lna_gain,
            requested_vga_gain=int(requested_vga),
            vga_gain=self.vga_gain,
            reason=self.active_profile_reason,
        )

    def reset_runtime_profile(self) -> None:
        self.configure_runtime(
            sample_rate=self.default_sample_rate,
            amp_enable=self.default_amp_enable,
            lna_gain=self.default_lna_gain,
            vga_gain=self.default_vga_gain,
            profile_id="default",
            profile_label="Default SDR",
            profile_reason="config_default",
        )

    # =========================================================================
    # STATE
    # =========================================================================
    def get_state(self) -> dict:
        """
        Return SDR state
        """

        alive = self.process is not None and self.process.poll() is None
        self._refresh_process_telemetry()

        return {
            "running": self.running and alive,
            "process_alive": alive,
            "freq_mhz": self.freq_mhz,
            "iq_path": self.iq_path,
            "sample_rate": self.sample_rate,
            "default_sample_rate": self.default_sample_rate,
            "startup_timeout": self.startup_timeout,
            "amp_enable": self.amp_enable,
            "lna_gain": self.lna_gain,
            "vga_gain": self.vga_gain,
            "active_profile_id": self.active_profile_id,
            "active_profile_label": self.active_profile_label,
            "active_profile_reason": self.active_profile_reason,
            "stderr_path": self.stderr_path,
            "last_error": self.last_error,
            "last_exit_code": self.last_exit_code,
            "last_start_attempt_at": self.last_start_attempt_at,
            "last_started_at": self.last_started_at,
            "last_stderr_excerpt": self.last_stderr_excerpt,
            "event_history": list(self.event_history),
        }

    # =========================================================================
    # HEALTH CHECK
    # =========================================================================
    def is_healthy(self) -> bool:
        """
        Validate SDR stream is alive (IQ growing)
        """

        state = self.get_state()

        if not state["running"]:
            return False

        try:
            size1 = os.path.getsize(self.iq_path)
            time.sleep(0.3)
            size2 = os.path.getsize(self.iq_path)

            healthy = size2 > size1

            if not healthy:
                print("⚠️ [SDR] IQ stream stalled")

            return healthy

        except Exception:
            return False
