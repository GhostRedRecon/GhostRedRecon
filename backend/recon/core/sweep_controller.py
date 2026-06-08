# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/recon/rf_sweep_controller.py
#
# VERSION:      v3.0.0 (INTELLIGENT ADAPTIVE RF SWEEP ENGINE)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# The RF Sweep Controller manages SDR tuning across RF channels to ensure
# continuous coverage of wireless spectrum relevant to red-team operations.
#
# Because SDR hardware can observe only a limited bandwidth at a time,
# the sweep controller must intelligently schedule channel observations.
#
#
# SYSTEM ARCHITECTURE
#
# SessionController
#        ↓
# RFSweepController      ← THIS MODULE
#        ↓
# SDRController.tune()
#        ↓
# LiveFFT
#        ↓
# ReconEngine
#        ↓
# SignalEngine
#        ↓
# IntelEngine
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. NON-BLOCKING SDR CONTROL
# -----------------------------------------------------------------------------
# Sweep operations must never block SDR streaming or FFT processing.
#
#
# 2. ADAPTIVE RF PRIORITIZATION
# -----------------------------------------------------------------------------
# Frequencies with detected activity should receive longer dwell time.
#
#
# 3. PHASE-BASED RF COVERAGE
# -----------------------------------------------------------------------------
# RF spectrum is scanned in phases to guarantee coverage of major
# wireless technologies:
#
#    WiFi
#    IoT (BLE / Zigbee)
#    Sub-GHz telemetry
#
#
# 4. RF ENVIRONMENT AWARENESS
# -----------------------------------------------------------------------------
# Sweep strategy adapts to spectral environment conditions.
#
#
# 5. HEATMAP-BASED INTELLIGENCE
# -----------------------------------------------------------------------------
# RF activity heatmaps guide channel prioritization.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • SDR frequency tuning
# • adaptive dwell scheduling
# • RF channel prioritization
# • RF heatmap tracking
# • phase-based spectrum scanning
#
#
# This module is NOT responsible for:
#
# • signal detection
# • protocol classification
# • device fingerprinting
#
# Those tasks are handled by ReconEngine.
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v2.x
#     basic adaptive scanning
#
# v3.x
#     heatmap decay
#     dynamic channel prioritization
#     environment-aware dwell
#     adaptive phase rotation
#
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • lock-free scanning loop
# • deterministic channel selection
# • bounded memory usage
# • SDR-safe tuning
#
# =============================================================================

import threading
import time
import logging
from collections import defaultdict

log = logging.getLogger("ghostrecon.sweep")


class RFSweepController:

    VERSION = "3.0.0"

    # -------------------------------------------------------------------------
    # DWELL SETTINGS
    # -------------------------------------------------------------------------

    BASE_DWELL = 0.20
    ACTIVE_DWELL = 0.60
    MAX_DWELL = 1.20

    LOOP_SLEEP = 0.05

    # Heatmap decay factor
    HEATMAP_DECAY = 0.95

    # -------------------------------------------------------------------------
    # RF CHANNEL DATABASE
    # -------------------------------------------------------------------------

    WIFI_24 = [2412, 2437, 2462]

    WIFI_5 = [
        5180, 5200, 5220, 5240,
        5745, 5765, 5785, 5805
    ]

    BLE = [
        2402, 2426, 2480
    ]

    ZIGBEE = [
        2405, 2410, 2415, 2420, 2425,
        2430, 2435, 2440, 2445, 2450,
        2455, 2460, 2465, 2470
    ]

    SUBGHZ_433 = [
        433.05, 433.30, 433.60, 433.92
    ]

    SUBGHZ_868 = [
        868.10, 868.30, 868.50
    ]

    # -------------------------------------------------------------------------
    # SWEEP PHASES
    # -------------------------------------------------------------------------

    PHASE_WIFI = "wifi"
    PHASE_IOT = "iot"
    PHASE_SUBGHZ = "subghz"

    BASE_PHASE_TIME = 4.0

    # -------------------------------------------------------------------------

    def __init__(self, sdr_controller, signal_engine=None):

        self._sdr = sdr_controller
        self._signal_engine = signal_engine

        self._running = False
        self._thread = None

        self._heatmap = defaultdict(float)
        self._hits = defaultdict(int)

        self._channel_index = 0
        self._priority_index = 0

        self._phase = self.PHASE_WIFI
        self._phase_start = time.time()

        self._environment_class = "normal"

        self._all_channels = (
            self.WIFI_24 +
            self.WIFI_5 +
            self.BLE +
            self.ZIGBEE +
            self.SUBGHZ_433 +
            self.SUBGHZ_868
        )

    # -------------------------------------------------------------------------
    # ENGINE CONTROL
    # -------------------------------------------------------------------------

    def start(self):

        if self._running:
            return

        self._running = True

        self._thread = threading.Thread(
            target=self._loop,
            daemon=True
        )

        self._thread.start()

        log.info("RF Sweep started (v%s)", self.VERSION)

    # -------------------------------------------------------------------------

    def stop(self):

        self._running = False

        if self._thread:
            self._thread.join(timeout=2)

        log.info("RF Sweep stopped")

    # -------------------------------------------------------------------------
    # MAIN LOOP
    # -------------------------------------------------------------------------

    def _loop(self):

        while self._running:

            try:

                self._update_phase()

                self._decay_heatmap()

                freq = self._select_channel()

                self._tune(freq)

                dwell = self._compute_dwell(freq)

                log.debug(
                    "Sweep → %.2f MHz | dwell %.2fs | phase=%s",
                    freq,
                    dwell,
                    self._phase
                )

                start = time.time()

                while time.time() - start < dwell and self._running:

                    self._update_heatmap(freq)

                    time.sleep(self.LOOP_SLEEP)

            except Exception as e:

                log.error("Sweep error: %s", e)

                time.sleep(0.5)

    # -------------------------------------------------------------------------
    # PHASE CONTROL
    # -------------------------------------------------------------------------

    def _phase_duration(self):

        activity = sum(self._heatmap.values())

        if activity > 50:
            return 8

        if activity > 10:
            return 6

        return self.BASE_PHASE_TIME

    # -------------------------------------------------------------------------

    def _update_phase(self):

        if time.time() - self._phase_start < self._phase_duration():
            return

        if self._phase == self.PHASE_WIFI:
            self._phase = self.PHASE_IOT

        elif self._phase == self.PHASE_IOT:
            self._phase = self.PHASE_SUBGHZ

        else:
            self._phase = self.PHASE_WIFI

        self._phase_start = time.time()

        log.debug("Sweep phase switched → %s", self._phase)

    # -------------------------------------------------------------------------
    # CHANNEL SELECTION
    # -------------------------------------------------------------------------

    def _phase_channels(self):

        if self._phase == self.PHASE_WIFI:
            return self.WIFI_24 + self.WIFI_5

        if self._phase == self.PHASE_IOT:
            return self.BLE + self.ZIGBEE

        return self.SUBGHZ_433 + self.SUBGHZ_868

    # -------------------------------------------------------------------------

    def _select_channel(self):

        channels = self._phase_channels()

        ranked = sorted(
            channels,
            key=lambda c: (self._heatmap[c], self._hits[c]),
            reverse=True
        )

        top = ranked[:5]

        if self._priority_index % 2 == 0 and top:

            freq = top[self._priority_index % len(top)]

        else:

            freq = channels[self._channel_index % len(channels)]

            self._channel_index += 1

        self._priority_index += 1

        return freq

    # -------------------------------------------------------------------------
    # DWELL TIME
    # -------------------------------------------------------------------------

    def _compute_dwell(self, freq):

        score = self._heatmap[freq]

        if self._environment_class == "quiet":
            base = self.BASE_DWELL * 0.6

        elif self._environment_class == "dense":
            base = self.ACTIVE_DWELL

        elif self._environment_class == "jammed":
            base = self.BASE_DWELL * 0.4

        else:
            base = self.BASE_DWELL

        if score == 0:
            return base

        if score < 5:
            return max(base, self.ACTIVE_DWELL)

        return self.MAX_DWELL

    # -------------------------------------------------------------------------
    # SDR TUNING
    # -------------------------------------------------------------------------

    def _tune(self, freq_mhz):

        if not self._sdr.is_running():
            return

        try:

            self._sdr.tune(freq_mhz * 1e6)

        except Exception as e:

            log.warning("Tune failed: %s", e)

    # -------------------------------------------------------------------------
    # HEATMAP DECAY
    # -------------------------------------------------------------------------

    def _decay_heatmap(self):

        for f in list(self._heatmap.keys()):

            self._heatmap[f] *= self.HEATMAP_DECAY

            if self._heatmap[f] < 0.1:
                del self._heatmap[f]

    # -------------------------------------------------------------------------
    # HEATMAP UPDATE
    # -------------------------------------------------------------------------

    def _update_heatmap(self, freq):

        if not self._signal_engine:
            return

        try:

            signals = self._signal_engine.get_recent_signals()

        except Exception:
            return

        score = 0

        for s in signals:

            sf = s.get("freq_mhz", 0)

            if abs(sf - freq) < 3:
                score += s.get("hit_count", 1)

        self._heatmap[freq] = (
            self._heatmap[freq] * 0.8 +
            score * 0.2
        )

        if score > 0:
            self._hits[freq] += 1

    # -------------------------------------------------------------------------
    # DYNAMIC CHANNEL DISCOVERY
    # -------------------------------------------------------------------------

    def add_priority_channel(self, freq):

        if freq not in self._all_channels:

            self._all_channels.append(freq)

            self._heatmap[freq] = 10

    # -------------------------------------------------------------------------
    # STATE
    # -------------------------------------------------------------------------

    def get_state(self):

        return {
            "running": self._running,
            "version": self.VERSION,
            "phase": self._phase,
            "channels_total": len(self._all_channels),
            "active_channels": len(self._heatmap)
        }
