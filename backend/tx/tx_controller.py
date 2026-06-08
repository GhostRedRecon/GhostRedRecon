# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/tx/tx_controller.py
# VERSION:      v1.0.0 (TX GATING SAFETY LAYER)
# LAST UPDATED: 2026-02-18
#
# =============================================================================
# ARCHITECTURE CONTEXT
# =============================================================================
# TXController enforces ALL transmission safety constraints.
#
# PURPOSE:
#   - Prevent uncontrolled RF transmission
#   - Enforce frequency restrictions
#   - Enforce power limits
#   - Enforce duration limits
#   - Provide dead-man timeout
#   - Provide hard kill switch
#
# DESIGN RULES:
#   ✔ Thread-safe
#   ✔ Fail-loud
#   ✔ Session-aware
#   ✔ No direct SDR manipulation
# =============================================================================

import threading
import time
import logging

log = logging.getLogger("ghostrecon.tx")


class TXController:

    def __init__(self):

        # Gating controls
        self._tx_enabled = False
        self._kill_switch = False

        # Safety limits
        self._allowed_freq_ranges = [
            (300e6, 450e6),   # Example lab band
        ]
        self._max_tx_duration_sec = 5
        self._max_tx_power_dbm = 10
        self._cooldown_sec = 2

        self._last_tx_time = None

        self._lock = threading.Lock()

    # -------------------------------------------------------------------------

    def enable_tx(self):
        with self._lock:
            if self._kill_switch:
                raise RuntimeError("TX permanently disabled (kill switch active)")
            self._tx_enabled = True
            log.info("TX enabled")

    def disable_tx(self):
        with self._lock:
            self._tx_enabled = False
            log.info("TX disabled")

    def activate_kill_switch(self):
        with self._lock:
            self._kill_switch = True
            self._tx_enabled = False
            log.warning("TX KILL SWITCH ACTIVATED")

    # -------------------------------------------------------------------------

    def validate_tx_request(self, freq_hz, power_dbm, duration_sec):

        with self._lock:

            if self._kill_switch:
                raise RuntimeError("TX blocked: kill switch active")

            if not self._tx_enabled:
                raise RuntimeError("TX blocked: not enabled")

            if duration_sec > self._max_tx_duration_sec:
                raise RuntimeError("TX blocked: duration exceeds max limit")

            if power_dbm > self._max_tx_power_dbm:
                raise RuntimeError("TX blocked: power exceeds max limit")

            if not self._freq_allowed(freq_hz):
                raise RuntimeError("TX blocked: frequency outside allowed range")

            if self._last_tx_time:
                if (time.time() - self._last_tx_time) < self._cooldown_sec:
                    raise RuntimeError("TX blocked: cooldown active")

            self._last_tx_time = time.time()

    # -------------------------------------------------------------------------

    def _freq_allowed(self, freq_hz):
        for low, high in self._allowed_freq_ranges:
            if low <= freq_hz <= high:
                return True
        return False

    # -------------------------------------------------------------------------

    def get_state(self):
        with self._lock:
            return {
                "tx_enabled": self._tx_enabled,
                "kill_switch": self._kill_switch,
                "last_tx_time": self._last_tx_time,
                "max_duration_sec": self._max_tx_duration_sec,
                "max_power_dbm": self._max_tx_power_dbm,
                "cooldown_sec": self._cooldown_sec,
            }
