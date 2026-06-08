# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/session/session_controller.py
# VERSION:      v11.0.0 (FINAL — SIGINT ORCHESTRATION CORE + PHASE 3 ACTIVE)
# UPDATED:      2026-03-22
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE
# =============================================================================
#
# Runtime
#   ↓
# SessionController (THIS FILE)
#   ↓
# ┌────────────────────────────────────────────┐
# │ SDRController  →  LiveFFT  →  ReconEngine │
# │                    ↓                     │
# │              SignalEngine                │
# │                    ↓                     │
# │        RFDeviceFusionEngine (Phase 3)    │
# └────────────────────────────────────────────┘
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Deterministic orchestration of RF intelligence pipeline.
#
# Guarantees:
# ✔ Strict startup order
# ✔ Verified readiness of each component
# ✔ Stable runtime lifecycle
# ✔ Continuous Phase 3 execution (device fusion)
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE
# -----------------------------------------------------------------------------
# ✔ Start SDR → FFT → Signal → Recon in correct order
# ✔ Validate pipeline readiness
# ✔ Maintain session lifecycle state
# ✔ Support retune without breaking pipeline
#
# PHASE 3 (CRITICAL)
# -----------------------------------------------------------------------------
# ✔ Execute device fusion continuously
# ✔ Feed fusion output back into SignalEngine (via runtime)
# ✔ Enable validator visibility of devices
#
# SAFETY
# -----------------------------------------------------------------------------
# ✔ No blocking loops
# ✔ Fail-safe background execution
# ✔ No crash propagation from fusion layer
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. DETERMINISTIC STARTUP
#    → no blind sleeps, only verified readiness
#
# 2. NON-BLOCKING PHASE 3
#    → device fusion runs in background thread
#
# 3. ZERO BREAKAGE POLICY
#    → no changes to existing external interfaces
#
# 4. FAIL-SAFE EXECUTION
#    → fusion errors never break pipeline
#
# 5. CONTROLLED LOOP EXECUTION
#    → bounded frequency, avoids CPU exhaustion
#
# =============================================================================
# 🔄 CHANGES (v11.0.0)
# =============================================================================
#
# ✔ Added Phase 3 execution loop (device fusion)
# ✔ Added runtime injection support
# ✔ Added safe background threading
# ✔ Preserved all existing interfaces
# ✔ Preserved deterministic startup behavior
#
# =============================================================================

import time
import threading
from typing import Optional


class SessionController:

    START_TIMEOUT = 10.0
    FUSION_INTERVAL = 1.0  # seconds (safe default)

    # =========================================================================
    # INIT
    # =========================================================================
    def __init__(
        self,
        sdr_controller,
        fft_engine,
        recon_engine,
        signal_engine,
        tx_controller=None,
        runtime=None,  # 🔥 NEW (non-breaking optional)
    ):
        self.sdr = sdr_controller
        self.fft = fft_engine
        self.recon = recon_engine
        self.signal = signal_engine
        self.tx = tx_controller

        self.runtime = runtime  # Phase 3 hook

        self._active = False
        self._current_freq = None
        self._fusion_thread = None
        self._session_started_at = None
        self._last_retune_at = None
        self._retune_count = 0
        self._band_dwell = {}
        self._band_sessions = {}
        self._current_band = None
        self._current_band_started_at = None
        self._event_timeline = []
        self._event_limit = 60
        self._lifecycle_lock = threading.RLock()

    # =========================================================================
    # STATE
    # =========================================================================
    def is_active(self) -> bool:
        return self._active

    def _classify_band(self, freq_mhz: Optional[float]) -> str:
        try:
            freq = float(freq_mhz)
        except Exception:
            return "unknown"

        if freq < 1000:
            if 860 <= freq <= 930:
                return "lora"
            return "subghz"
        if 2400 <= freq <= 2485:
            if abs(freq - 2402) <= 3 or abs(freq - 2426) <= 3 or abs(freq - 2480) <= 3:
                return "ble"
            if 2405 <= freq <= 2480:
                return "zigbee"
            return "wifi"
        return "wideband"

    def _record_band_transition(self, next_freq: Optional[float]) -> None:
        now = time.time()

        if self._current_band and self._current_band_started_at:
            dwell = max(0.0, now - self._current_band_started_at)
            self._band_dwell[self._current_band] = self._band_dwell.get(self._current_band, 0.0) + dwell

        if next_freq is None:
            self._current_band = None
            self._current_band_started_at = None
            return

        next_band = self._classify_band(next_freq)
        self._current_band = next_band
        self._current_band_started_at = now
        self._band_sessions[next_band] = self._band_sessions.get(next_band, 0) + 1

    def get_telemetry(self) -> dict:
        now = time.time()
        dwell = dict(self._band_dwell)
        if self._active and self._current_band and self._current_band_started_at:
            dwell[self._current_band] = dwell.get(self._current_band, 0.0) + max(0.0, now - self._current_band_started_at)

        return {
            "session_started_at": self._session_started_at,
            "last_retune_at": self._last_retune_at,
            "retune_count": self._retune_count,
            "current_band": self._current_band,
            "band_dwell_seconds": {key: round(value, 2) for key, value in dwell.items()},
            "band_session_counts": dict(self._band_sessions),
            "recent_events": self.get_event_timeline(10),
        }

    def _record_event(self, category: str, message: str, severity: str = "info", **details) -> None:
        event = {
            "timestamp": time.time(),
            "category": category,
            "severity": severity,
            "message": message,
            "details": details,
        }
        self._event_timeline.append(event)
        if len(self._event_timeline) > self._event_limit:
            self._event_timeline = self._event_timeline[-self._event_limit :]
        if self.runtime and hasattr(self.runtime, "record_rf_event"):
            try:
                self.runtime.record_rf_event(category, message, details, severity=severity)
            except Exception:
                pass

    def get_event_timeline(self, limit: int = 20) -> list[dict]:
        if limit <= 0:
            return []
        return list(self._event_timeline[-limit:])

    # =========================================================================
    # WAIT HELPERS
    # =========================================================================
    def _wait_until(self, condition, timeout, label):
        start = time.time()

        while time.time() - start < timeout:
            if condition():
                return True
            time.sleep(0.2)

        raise RuntimeError(f"{label} timeout")

    # =========================================================================
    # START
    # =========================================================================
    def start(self, freq_mhz: Optional[float] = None):
        with self._lifecycle_lock:
            print("\n🧠 ================= SESSION START =================")
            self._record_event("session", "Session start requested", freq_mhz=freq_mhz)

            if self._active:
                print("⚠️ Already active")
                if freq_mhz:
                    return self.retune(freq_mhz)
                return {"status": "already_running"}

            if freq_mhz is None:
                raise ValueError("Frequency required")

            try:
                if self.runtime and getattr(self.runtime, "device_fusion", None) and hasattr(self.runtime.device_fusion, "reset"):
                    self.runtime.device_fusion.reset()

                # -----------------------------------------------------
                # SDR
                # -----------------------------------------------------
                print(f"📡 Starting SDR @ {freq_mhz} MHz")
                result = self.sdr.start(freq_mhz=freq_mhz)

                if result.get("status") != "started":
                    raise RuntimeError(f"SDR failed → {result}")

                self._wait_until(
                    lambda: self.sdr.get_state().get("running"),
                    self.START_TIMEOUT,
                    "SDR start"
                )

                print("✅ SDR READY")

                # -----------------------------------------------------
                # FFT
                # -----------------------------------------------------
                print("📊 Starting FFT")
                self.fft.start()

                self._wait_until(
                    lambda: self.fft.is_running(),
                    self.START_TIMEOUT,
                    "FFT start"
                )

                print("✅ FFT READY")

                # -----------------------------------------------------
                # SIGNAL ENGINE
                # -----------------------------------------------------
                print("🧠 Starting SignalEngine")
                self.signal.start()

                self._wait_until(
                    lambda: self.signal.get_stats().get("running", False),
                    self.START_TIMEOUT,
                    "SignalEngine start"
                )

                print("✅ SIGNAL READY")

                # -----------------------------------------------------
                # RECON ENGINE
                # -----------------------------------------------------
                print("🧠 Starting ReconEngine")
                self.recon.start(self.sdr, self.fft)

                self._wait_until(
                    lambda: self.recon.get_stats().get("running"),
                    self.START_TIMEOUT,
                    "Recon start"
                )

                print("✅ RECON READY")

                # -----------------------------------------------------
                # FINAL VALIDATION
                # -----------------------------------------------------
                self._wait_until(
                    lambda: self._pipeline_ready(),
                    self.START_TIMEOUT,
                    "Pipeline ready"
                )

                self._active = True
                self._current_freq = freq_mhz
                self._session_started_at = time.time()
                self._last_retune_at = self._session_started_at
                self._retune_count = 0
                self._band_dwell = {}
                self._band_sessions = {}
                self._record_band_transition(freq_mhz)

                # 🔥 PHASE 3 ACTIVATION
                self._start_phase3_loop()
                self._record_event("session", "Session started", freq_mhz=freq_mhz, band=self._current_band)

                print("🚀 PIPELINE FULLY ACTIVE")
                print("==================================================\n")

                return {"status": "started"}

            except Exception as e:
                print(f"🔥 START FAILED → {e}")
                self._record_event("session", "Session start failed", severity="error", freq_mhz=freq_mhz, error=str(e))
                self.stop()
                raise

    # =========================================================================
    # PHASE 3 LOOP
    # =========================================================================
    def _start_phase3_loop(self):
        """
        Starts background device fusion loop.
        """

        if self._fusion_thread and self._fusion_thread.is_alive():
            return  # already running

        def loop():
            while self._active:
                try:
                    if self.runtime and hasattr(self.runtime, "run_device_fusion"):
                        self.runtime.run_device_fusion()
                except Exception:
                    pass  # fail-safe

                time.sleep(self.FUSION_INTERVAL)

        self._fusion_thread = threading.Thread(target=loop, daemon=True)
        self._fusion_thread.start()

    # =========================================================================
    # PIPELINE CHECK
    # =========================================================================
    def _pipeline_ready(self):

        sdr_ok = self.sdr.get_state().get("running")
        fft_ok = self.fft.is_running()
        recon_ok = self.recon.get_stats().get("running")
        signal_ok = self.signal.get_stats().get("running", False)

        return all([sdr_ok, fft_ok, recon_ok, signal_ok])

    # =========================================================================
    # RETUNE
    # =========================================================================
    def retune(self, freq_mhz: float):
        with self._lifecycle_lock:
            print(f"\n🔄 Retuning → {freq_mhz} MHz")
            self._record_event("retune", "Retune requested", freq_mhz=freq_mhz)

            if not self._active:
                raise RuntimeError("Session not active")

            result = self.sdr.start(freq_mhz=freq_mhz)

            if result.get("status") not in ["started", "retuned"]:
                raise RuntimeError(f"Retune failed → {result}")

            self._wait_until(
                lambda: abs(self.sdr.get_state().get("freq_mhz") - freq_mhz) < 0.1,
                self.START_TIMEOUT,
                "Retune"
            )

            # Flush old-band detections so post-retune intel reflects the new center.
            if self.signal and hasattr(self.signal, "reset"):
                self.signal.reset()
            if self.runtime and getattr(self.runtime, "device_fusion", None) and hasattr(self.runtime.device_fusion, "reset"):
                self.runtime.device_fusion.reset()

            self._last_retune_at = time.time()
            self._retune_count += 1
            self._record_band_transition(freq_mhz)
            self._current_freq = freq_mhz
            self._record_event("retune", "Retune completed", freq_mhz=freq_mhz, band=self._current_band)

            print("✅ RETUNE OK\n")

            return {"status": "retuned", "freq_mhz": freq_mhz}

    # =========================================================================
    # STOP
    # =========================================================================
    def stop(self):
        with self._lifecycle_lock:
            print("\n🛑 STOPPING SESSION")
            previous_freq = self._current_freq

            try:
                self._active = False  # stop loop first
                self._record_band_transition(None)

                if self.recon:
                    self.recon.stop()

                if self.signal:
                    self.signal.stop()

                if self.fft:
                    self.fft.stop()

                if self.sdr:
                    self.sdr.stop()

            except Exception as e:
                print(f"🔥 STOP ERROR → {e}")
                self._record_event("session", "Session stop error", severity="error", freq_mhz=previous_freq, error=str(e))

            self._current_freq = None
            self._current_band = None
            self._current_band_started_at = None
            self._record_event("session", "Session stopped", freq_mhz=previous_freq)

            print("🛑 SESSION STOPPED\n")
